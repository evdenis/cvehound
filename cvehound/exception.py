from typing import Any


class UnsupportedVersion(Exception):
    def __init__(self, spatch_version: int, cve: str, rule_version: int) -> None:
        # Convert version integer (e.g., 107) to dotted string (e.g., "1.0.7")
        # Version encoding: XYZ represents version X.Y.Z
        self.spatch_version = (
            f'{spatch_version // 100}.{(spatch_version // 10) % 10}.{spatch_version % 10}'
        )
        self.cve = cve
        self.rule_version = f'{rule_version // 100}.{(rule_version // 10) % 10}.{rule_version % 10}'


class SpatchNotFound(Exception):
    """No usable spatch binary: carries the message for the source that failed.

    find_spatch() reports every resolution failure this way -- an explicitly
    named binary that is missing, or nothing found at all -- so callers handle
    one exception instead of an exception plus a None return.
    """


class SpatchError(Exception):
    """spatch exited non-zero: report what it said, not just how it was called.

    subprocess's CalledProcessError renders the full argv -- a kilobyte of
    include paths -- and drops stderr, so a crashed run is indistinguishable
    from any other. spatch is also silent under --very-quiet until it dies,
    and OCaml turns an uncaught exception (a full /tmp, say) into a bare
    exit code 2, which makes the captured stderr the only diagnosis there is.
    """

    #: stderr is unbounded (parse errors repeat per file); keep the tail, where
    #: the fatal message lands.
    MAX_STDERR = 2000

    def __init__(self, cve: str, kernel: str, returncode: int, stderr: str) -> None:
        self.cve = cve
        self.kernel = kernel
        self.returncode = returncode
        self.stderr = stderr
        tail = self.stderr_tail
        super().__init__(self._summary() + (f'\n{tail}' if tail else ' (no stderr)'))

    @property
    def stderr_tail(self) -> str:
        tail = self.stderr.strip()
        if len(tail) > self.MAX_STDERR:
            tail = '...' + tail[-self.MAX_STDERR :]
        return tail

    def _summary(self) -> str:
        return f'spatch failed with exit code {self.returncode} on {self.cve} in {self.kernel}'

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        # Raised inside ProcessPoolExecutor workers, so it has to survive a
        # pickle round trip: the default reduce replays __init__ with the
        # single formatted message BaseException recorded in .args.
        return (self.__class__, (self.cve, self.kernel, self.returncode, self.stderr))


class SpatchTimeout(SpatchError):
    """A rule blew its time budget: which budget, and on what file.

    Subclasses SpatchError so callers that only care the rule failed keep
    working. The distinction is worth drawing because a timeout is never an
    environment problem -- it is the rule, and the fix is a cheaper pattern
    (docs/WRITING_RULES.md -> "Rule 8: Keep the grep query selective").

    Two budgets produce it. spatch's own --timeout counts CPU-seconds inside the
    matching engine and usually names the file it gave up on; the outer
    wall-clock watchdog counts everything, including the phases --timeout cannot
    see, and names nothing. `files` is empty whenever spatch did not say, which
    is not the same as "no file was to blame".
    """

    def __init__(
        self,
        cve: str,
        kernel: str,
        returncode: int,
        stderr: str,
        timeout: int,
        files: list[str] | None = None,
        wall: bool = False,
    ) -> None:
        self.timeout = timeout
        self.files = files or []
        self.wall = wall
        super().__init__(cve, kernel, returncode, stderr)

    def _summary(self) -> str:
        budget = f'{self.timeout}s of wall time' if self.wall else f'{self.timeout} CPU-seconds'
        where = f' on {", ".join(self.files)}' if self.files else ''
        return f'{self.cve}: spatch exceeded its budget of {budget}{where} in {self.kernel}'

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (self.__class__, super().__reduce__()[1] + (self.timeout, self.files, self.wall))
