"""Plain-subprocess git access: what the CLI needs to read a tree at any revision.

Two persistent `git cat-file` children answer object lookups (a header is ~9us
over the pipe instead of a fork per question), and everything else is a
one-shot `git` command. The object-reading half is the ObjectReader protocol
that cvehound.oracle.BlobMaterializer consumes; GitPython's `Repo.git`
satisfies the same protocol, which is why the test suite and the CLI share the
materializer without the CLI depending on GitPython.

Every command runs under _spatch_env(): the user's global gitconfig is out of
the picture and safe.directory is granted for the scanned tree, so a checkout
owned by another user reads the same way it scans.
"""

import codecs
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterable, Iterator

from cvehound import _spatch_env
from cvehound.exception import GitError

# The abbreviation commits are matched on when a caller has only a prefix:
# what Fixes: trailers use, and unambiguous in a kernel-sized object database.
ABBREV = 12


class GitRepo:
    """One repository, addressed from its toplevel.

    The toplevel requirement is not pedantry: blobs are named `<rev>:<relpath>`
    with relpaths taken from rule headers, so a --kernel pointing inside the
    tree would resolve every one of them against the wrong prefix.
    """

    def __init__(self, path: str) -> None:
        if shutil.which('git') is None:
            raise GitError('git not found on PATH')
        self.path = os.path.abspath(path)
        self.env = _spatch_env(self.path)
        self._pipes: dict[str, subprocess.Popen[bytes]] = {}
        self._lock = threading.Lock()
        try:
            out = self.run('rev-parse', '--show-toplevel', '--git-common-dir')
        except GitError as err:
            raise GitError(f'{path} is not a git repository: {err}') from err
        toplevel, common = out.splitlines()[:2]
        self.toplevel = os.path.realpath(toplevel)
        self.git_dir = os.path.realpath(os.path.join(self.path, common))
        if os.path.realpath(self.path) != self.toplevel:
            raise GitError(f'{path} is inside the repository at {self.toplevel}; pass the root')

    def __enter__(self) -> 'GitRepo':
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- one-shot commands -------------------------------------------------

    def _exec(
        self, *args: str, input: bytes | None = None, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ['git', *args],
            cwd=self.path,
            env=env or self.env,
            input=input,
            capture_output=True,
            check=False,
        )

    def run(self, *args: str, input: bytes | None = None, env: dict[str, str] | None = None) -> str:
        """stdout of `git ARGS`, or GitError carrying stderr."""
        run = self._exec(*args, input=input, env=env)
        if run.returncode != 0:
            stderr = run.stderr.decode(errors='replace').strip()
            raise GitError(stderr or f'git {args[0]} exited with {run.returncode}')
        return run.stdout.decode(errors='replace')

    def _chunks(self, *args: str) -> Iterator[str]:
        """stdout of `git ARGS` as it arrives, decoded; GitError once it ends
        non-zero. For output that must not be held whole: a range's messages
        run to hundreds of MB, and every consumer reads them once."""
        proc = subprocess.Popen(
            ['git', *args],
            cwd=self.path,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        stdout = proc.stdout
        assert stdout is not None
        try:
            for chunk in iter(lambda: stdout.read(1 << 16), b''):
                yield decoder.decode(chunk)
            yield decoder.decode(b'', final=True)
            _, stderr = proc.communicate()
            if proc.returncode != 0:
                raise GitError(
                    stderr.decode(errors='replace').strip()
                    or f'git {args[0]} exited with {proc.returncode}'
                )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def rev_parse(self, rev: str) -> str:
        """The commit a revision names, or GitError saying it is not here."""
        try:
            return self.run(
                'rev-parse', '--verify', '--quiet', '--end-of-options', f'{rev}^{{commit}}'
            ).strip()
        except GitError as err:
            raise GitError(
                f'unknown revision {rev!r} in {self.toplevel} (not fetched, or a shallow clone?)'
            ) from err

    def has_commit(self, name: str) -> bool:
        try:
            self.get_object_header(f'{name}^{{commit}}')
        except ValueError:
            return False
        return True

    def describe(self, sha: str) -> str | None:
        """`git describe --tags`, or None when no tag reaches the commit."""
        try:
            return self.run('describe', '--tags', '--end-of-options', sha).strip() or None
        except GitError:
            return None

    def is_dirty(self) -> bool:
        """Whether tracked files differ from HEAD. Writes the index: never
        call it after the sandbox is installed."""
        return bool(self.run('status', '--porcelain', '--untracked-files=no').strip())

    def diff_names(self, a: str, b: str) -> list[str]:
        """Paths that differ between two tree-ishes, both ends of a rename
        listed, so a rule naming either name of a moved file matches."""
        out = self.run('diff', '--name-only', '--no-renames', '-z', a, b, '--')
        return sorted({p for p in out.split('\0') if p})

    def log_commits(self, a: str, b: str, paths: Iterable[str]) -> list[str]:
        """Commits in a..b that touch any of the paths, oldest first."""
        out = self.run(
            'log',
            '--format=%H',
            '--reverse',
            '--topo-order',
            '--ancestry-path',
            f'{a}..{b}',
            '--',
            *paths,
        )
        return out.split()

    def log_messages(
        self,
        rev: str,
        grep: Iterable[str] = (),
        since: str | None = None,
        no_merges: bool = False,
    ) -> Iterator[tuple[str, str]]:
        """(sha, full message) for the commits reachable from rev, streamed.

        `grep` needles are fixed strings ORed together, the way git treats
        several --grep; attributing a match to a needle is the caller's job,
        since it also has to decide what the match means in context.
        """
        args = ['log', '--format=%H%x00%B%x00', '--fixed-strings']
        for needle in grep:
            args.append(f'--grep={needle}')
        if since:
            args.append(f'--since={since}')
        if no_merges:
            args.append('--no-merges')
        args.append(rev)
        pending = ''
        sha: str | None = None
        for chunk in self._chunks(*args):
            records = (pending + chunk).split('\0')
            pending = records.pop()
            for record in records:
                if sha is None:
                    # The record separator git appends lands in front of the
                    # next sha; strip() takes it back off.
                    sha = record.strip() or None
                else:
                    yield sha, record
                    sha = None

    def reachable(self, sha: str, prefixes: set[str]) -> set[str]:
        """Which of the ABBREV-long prefixes name a commit in sha's history.

        One streamed `rev-list`, whatever the number of prefixes: a kernel
        history is a million commits, and a merge-base fork per question costs
        more than reading them once.
        """
        found: set[str] = set()
        pending = ''
        for chunk in self._chunks('rev-list', sha):
            lines = (pending + chunk).split('\n')
            pending = lines.pop()
            for line in lines:
                prefix = line[:ABBREV]
                if prefix in prefixes:
                    found.add(prefix)
        return found

    def commit_subject(self, sha: str) -> str:
        return self.run('show', '-s', '--format=%h %s', '--end-of-options', sha).strip()

    def is_ancestor(self, ancestor: str, descendant: str) -> bool | None:
        """merge-base --is-ancestor, or None when either commit is not here."""
        if not (self.has_commit(ancestor) and self.has_commit(descendant)):
            return None
        run = self._exec('merge-base', '--is-ancestor', ancestor, descendant)
        if run.returncode in (0, 1):
            return run.returncode == 0
        raise GitError(run.stderr.decode(errors='replace').strip())

    def patch_tree(self, base: str, patch: bytes) -> str:
        """The tree a patch produces on top of a tree-ish, as a tree oid.

        Applied in a private index, so neither the working tree nor the real
        index is touched; what does land is the resulting blobs and trees as
        dangling objects in the object database, which git gc reclaims.
        """
        with tempfile.TemporaryDirectory(prefix='cvehound-patch-') as scratch:
            env = dict(self.env, GIT_INDEX_FILE=os.path.join(scratch, 'index'))
            self.run('read-tree', base, env=env)
            try:
                self.run('apply', '--cached', '-', input=patch, env=env)
            except GitError as err:
                raise GitError(f'patch does not apply on {base}: {err}') from err
            return self.run('write-tree', env=env).strip()

    def read_paths(self) -> tuple[str, ...]:
        """What a sandbox has to grant read-only for git to keep answering after
        the lock: the tree, its git dir, and the object stores it borrows."""
        return (self.toplevel, self.git_dir, *self.alternates())

    def alternates(self) -> list[str]:
        """Object stores this repository borrows from (git clone --shared,
        worktrees of another clone): a sandbox has to grant them too."""
        objects = os.path.join(self.git_dir, 'objects')
        path = os.path.join(objects, 'info', 'alternates')
        try:
            with open(path, encoding='utf-8') as fh:
                lines = [line.strip() for line in fh]
        except OSError:
            return []
        return [
            os.path.realpath(os.path.join(objects, line))
            for line in lines
            if line and not line.startswith('#')
        ]

    # -- ObjectReader: persistent cat-file pipes ---------------------------

    def _pipe(self, flag: str) -> subprocess.Popen[bytes]:
        proc = self._pipes.get(flag)
        if proc is None or proc.poll() is not None:
            proc = self._pipes[flag] = subprocess.Popen(
                ['git', 'cat-file', flag],
                cwd=self.path,
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        return proc

    @staticmethod
    def _ask(proc: subprocess.Popen[bytes], name: str) -> bytes:
        if '\n' in name:
            raise ValueError(f'object name with a newline: {name!r}')
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(name.encode() + b'\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise GitError('git cat-file exited unexpectedly')
        return line

    @staticmethod
    def _parse_header(name: str, line: bytes) -> tuple[str, str, int]:
        fields = line.decode(errors='replace').rstrip('\n').split(' ')
        if len(fields) < 3:
            # "<name> missing", "<name> ambiguous": the same ValueError GitPython
            # raises, which is what object_header() turns into None.
            raise ValueError(f'{name}: {fields[-1]}')
        return fields[0], fields[1], int(fields[2])

    def get_object_header(self, name: str) -> tuple[str, str, int]:
        with self._lock:
            line = self._ask(self._pipe('--batch-check'), name)
        return self._parse_header(name, line)

    def get_object_data(self, name: str) -> tuple[str, str, int, bytes]:
        with self._lock:
            proc = self._pipe('--batch')
            line = self._ask(proc, name)
            oid, otype, size = self._parse_header(name, line)
            assert proc.stdout is not None
            data = proc.stdout.read(size)
            proc.stdout.read(1)  # the LF cat-file appends after the contents
        return oid, otype, size, data

    def ls_tree(self, *args: str) -> str:
        return self.run('ls-tree', *args)

    def close(self) -> None:
        """Reap the cat-file children. Idempotent; the pipes reopen on demand."""
        pipes, self._pipes = self._pipes, {}
        for proc in pipes.values():
            if proc.stdin is not None:
                proc.stdin.close()
            if proc.stdout is not None:
                proc.stdout.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
