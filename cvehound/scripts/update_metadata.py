#!/usr/bin/env python3

import contextlib
import glob
import gzip
import json
import os
import re
import subprocess
import sys
from functools import cache
from typing import Any
from urllib.request import Request, urlopen

import yaml

KERNEL_VULNS_REPO = 'https://git.kernel.org/pub/scm/linux/security/vulns.git'
CIP_KERNEL_SEC_REPO = 'https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec.git'
CISA_KEV_URLS = (
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    # GitHub mirror of the same catalog, in case the feed above is unreachable
    'https://raw.githubusercontent.com/cisagov/kev-data/develop/'
    'known_exploited_vulnerabilities.json',
)
COMMIT_ID = re.compile(r'[0-9a-f]{7,40}')

# CIP kernel-sec has no rejected state. It records why an issue is not tracked in
# a free text 'ignore: all:' note, which mixes genuine rejections in with "we are
# not backporting this". These are the openings that mean the CVE itself is not a
# kernel vulnerability; anything else ("Minor issue", "won't fix", ...) is not.
CIP_REJECTED_PREFIXES = (
    'This is not a kernel bug',
    'This is not a bug',
    'This CVE was rejected',
    'This CVE is rejected',
    'Not a kernel',
    'Not kernel',
    'Not a real',
    'Not a security',
)
CIP_REJECTED_MARKERS = (
    'Android',
    'duplicate',
    'closed source',
    'out-of-tree',
    'Bogus',
    'Invalid',
)


def get_exploit_status_from_cisa_kev() -> set[str]:
    """Fetch exploit status from the CISA Known Exploited Vulnerabilities catalog."""
    exploited_cves: set[str] = set()

    for url in CISA_KEV_URLS:
        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
        except Exception as e:
            print(f'Warning: Failed to fetch CISA KEV data from {url}: {e}', file=sys.stderr)
            continue

        # CISA KEV format has vulnerabilities in a list
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID')
            if cve_id:
                exploited_cves.add(cve_id)
        break

    return exploited_cves


def dropempty(info: dict[str, Any]) -> dict[str, Any]:
    """Drop keys with an empty value so they never overwrite data from another source."""
    return {key: value for key, value in info.items() if value}


def get_commit_id(value: Any) -> str:
    """Return value if it looks like a git commit id, an empty string otherwise.

    Both sources use placeholders where a commit is unknown: 'never' in CIP
    kernel-sec, '0' in the kernel.org git ranges.
    """
    if isinstance(value, str) and COMMIT_ID.fullmatch(value):
        return value
    return ''


@cache
def resolve_commit(repo: str, value: Any) -> str:
    """Resolve a source commit id to a full hash, or return an empty string."""
    commit = get_commit_id(value)
    if not commit:
        return ''
    if len(commit) == 40:
        return commit
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--verify', f'{commit}^{{commit}}'],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        return ''


@cache
def is_ancestor(repo: str, ancestor: str, descendant: str) -> bool:
    """Tell whether ancestor is reachable from descendant."""
    return (
        subprocess.run(
            ['git', 'merge-base', '--is-ancestor', ancestor, descendant],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


@cache
def get_mainline_commits(repo: str, mainline: str) -> frozenset[str]:
    """Return all commits reachable from the selected mainline tip."""
    commits = subprocess.check_output(
        ['git', 'rev-list', mainline],
        cwd=repo,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return frozenset(commits.splitlines())


def get_mainline_commit(repo: str) -> str:
    """Return the tip used to distinguish mainline commits from backports."""
    for ref in ('refs/remotes/origin/master', 'refs/heads/master', 'HEAD'):
        try:
            return subprocess.check_output(
                ['git', 'rev-parse', '--verify', f'{ref}^{{commit}}'],
                cwd=repo,
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError(f'No usable mainline commit in {repo}')


def select_topological_commit(
    repo: str,
    values: list[Any],
    mainline: str,
    *,
    latest: bool,
    source: str,
) -> str:
    """Select the unique earliest or latest source commit in mainline history."""
    commits = {
        commit
        for value in values
        if (commit := resolve_commit(repo, value))
        and commit in get_mainline_commits(repo, mainline)
    }
    if not commits:
        return ''

    if latest:
        extremes = [
            commit
            for commit in commits
            if all(is_ancestor(repo, other, commit) for other in commits)
        ]
    else:
        extremes = [
            commit
            for commit in commits
            if all(is_ancestor(repo, commit, other) for other in commits)
        ]

    if len(extremes) == 1:
        return extremes[0]

    direction = 'latest' if latest else 'earliest'
    print(
        f'Warning: {source} has no unique {direction} mainline commit: {sorted(commits)}',
        file=sys.stderr,
    )
    return ''


def is_cip_rejected(data: dict[str, Any]) -> bool:
    """Tell whether a CIP kernel-sec issue says the CVE itself is not valid.

    Only the 'all' key counts. The per branch keys mean "not applicable to this
    branch", which says nothing about the CVE.
    """
    message = (data.get('ignore') or {}).get('all')
    if not isinstance(message, str):
        return False
    return message.startswith(CIP_REJECTED_PREFIXES) or any(
        marker in message for marker in CIP_REJECTED_MARKERS
    )


def get_commit_info(repo: str, commit: str) -> tuple[int, str] | None:
    """Get the commit date and subject of a commit from a git repository."""
    try:
        out = subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct%n%s', commit],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        )
    except Exception:
        return None
    date, _, subject = out.partition('\n')
    return int(date), subject.strip()


def get_cache_dir() -> str:
    """Directory to keep the cloned CVE repositories in."""
    cache = os.environ.get('CVEHOUND_CACHE')
    if not cache:
        xdg = os.environ.get('XDG_CACHE_HOME') or os.path.join(os.path.expanduser('~'), '.cache')
        cache = os.path.join(xdg, 'cvehound')
    return cache


def clone_or_update_repo(url: str, path: str, depth: int = 1) -> bool:
    """Clone a git repository or update it if it already exists."""
    if os.path.isdir(os.path.join(path, '.git')):
        print(f'Updating {path}...')
        try:
            subprocess.check_call(
                ['git', 'pull'],
                cwd=path,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            print(f'Warning: Failed to update {path}', file=sys.stderr)
            return False
    else:
        print(f'Cloning {url}...')
        os.makedirs(path, exist_ok=True)
        try:
            subprocess.check_call(
                ['git', 'clone', '--depth', str(depth), url, path],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as e:
            print(f'Warning: Failed to clone {url}: {e}', file=sys.stderr)
            return False
    return True


def parse_kernel_vulns_cve(
    cve_file: str, repo: str, mainline: str
) -> tuple[str | None, dict[str, Any] | None]:
    """Parse a CVE from the kernel.org vulns.git JSON format."""
    with open(cve_file) as fh:
        data = json.load(fh)

    # The spelling of the id is not consistent across the corpus: published
    # records use 'cveId', rejected ones 'cveID'. The file name always agrees.
    meta = data.get('cveMetadata', {})
    cve_id = meta.get('cveId') or meta.get('cveID') or os.path.basename(cve_file)[: -len('.json')]
    if not cve_id.startswith('CVE-'):
        return None, None

    cna = data.get('containers', {}).get('cna', {})

    # Every branch that carries the fix is listed as its own git range. The
    # 'version' of a range is the commit that introduced the bug, the 'lessThan'
    # is the commit that fixed it. Select by topology because source order is not
    # an API and stable backports may also exist in the local object database.
    ranges = [
        version
        for item in cna.get('affected', [])
        for version in item.get('versions', [])
        if version.get('versionType') == 'git'
        and version.get('status') == 'affected'
        and version.get('lessThan')
    ]

    info: dict[str, Any] = {}
    fix = select_topological_commit(
        repo,
        [item['lessThan'] for item in ranges],
        mainline,
        latest=True,
        source=cve_id,
    )
    if fix:
        info['fixes'] = fix
        paired_breaks = [
            item.get('version') for item in ranges if resolve_commit(repo, item['lessThan']) == fix
        ]
        info['breaks'] = select_topological_commit(
            repo,
            paired_breaks,
            mainline,
            latest=False,
            source=cve_id,
        )

    return cve_id, dropempty(info)


def parse_cip_kernel_sec_cve(
    cve_file: str, repo: str, mainline: str
) -> tuple[str | None, dict[str, Any] | None]:
    """Parse a CVE from the CIP kernel-sec YAML format."""
    with open(cve_file) as fh:
        data = yaml.safe_load(fh)

    if not data:
        return None, None

    cve_id = os.path.basename(cve_file).replace('.yml', '')

    # Only the 'mainline' key holds upstream commits. The per-distro keys can carry
    # package versions instead ("version:5.4.0-9.12"), and both keys degrade to the
    # string 'never' for issues that were never introduced or never fixed upstream.
    # The 'description' is hand written here and is not the commit subject, so it
    # is deliberately not used as cmt_msg.
    info: dict[str, Any] = {}
    for key, field, latest in (
        ('fixed-by', 'fixes', True),
        ('introduced-by', 'breaks', False),
    ):
        commits = (data.get(key) or {}).get('mainline')
        if isinstance(commits, str):
            commits = [commits]
        if commits:
            info[field] = select_topological_commit(
                repo,
                commits,
                mainline,
                latest=latest,
                source=cve_id,
            )

    if is_cip_rejected(data):
        info['rejected'] = True

    return cve_id, dropempty(info)


def fetch_kernel_vulns_data(temp_dir: str, repo: str, mainline: str) -> dict[str, dict[str, Any]]:
    """Fetch CVE data from the kernel.org vulns.git repository."""
    vulns_dir = os.path.join(temp_dir, 'kernel-vulns')
    cves: dict[str, dict[str, Any]] = {}

    if not clone_or_update_repo(KERNEL_VULNS_REPO, vulns_dir):
        return cves

    # A rejected record keeps its full contents and still claims state PUBLISHED,
    # so the directory it sits in is the only reliable sign that it was withdrawn.
    for state in ('published', 'rejected'):
        cve_pattern = os.path.join(vulns_dir, 'cve', state, '**', 'CVE-*.json')
        for cve_file in glob.glob(cve_pattern, recursive=True):
            try:
                cve_id, info = parse_kernel_vulns_cve(cve_file, repo, mainline)
                if cve_id and info:
                    if state == 'rejected':
                        info['rejected'] = True
                    cves[cve_id] = info
            except Exception as e:
                print(f'Warning: Failed to parse {cve_file}: {e}', file=sys.stderr)

    return cves


def fetch_cip_kernel_sec_data(temp_dir: str, repo: str, mainline: str) -> dict[str, dict[str, Any]]:
    """Fetch CVE data from the CIP kernel-sec GitLab repository."""
    cip_dir = os.path.join(temp_dir, 'cip-kernel-sec')
    cves: dict[str, dict[str, Any]] = {}

    if clone_or_update_repo(CIP_KERNEL_SEC_REPO, cip_dir):
        cve_pattern = os.path.join(cip_dir, 'issues', 'CVE-*.yml')
        for cve_file in glob.glob(cve_pattern):
            try:
                cve_id, info = parse_cip_kernel_sec_cve(cve_file, repo, mainline)
                if cve_id and info:
                    cves[cve_id] = info
            except Exception as e:
                print(f'Warning: Failed to parse {cve_file}: {e}', file=sys.stderr)

    return cves


def merge_cve_data(
    kernel_vulns_cves: dict[str, dict[str, Any]], cip_cves: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Merge CVE data from both sources, preferring kernel.org vulns.git."""
    merged: dict[str, dict[str, Any]] = {}

    # Start with CIP data, which covers the older CVEs, and let kernel.org win key
    # by key: it is the CNA for the kernel and its records are generated from the
    # commits themselves.
    for cves in (cip_cves, kernel_vulns_cves):
        for cve_id, info in cves.items():
            merged.setdefault(cve_id, {}).update(info)

    return merged


def write_metadata(js: dict[str, Any], filename: str) -> None:
    """Atomically write the metadata blob, refusing suspicious regressions.

    A failed fetch of the upstream sources must never destroy a good blob:
    an empty result is rejected outright, and a large shrink against an
    existing readable blob is rejected too (write to a fresh path to
    override).  The write goes through a temp file + os.replace so an
    interrupted run cannot leave a truncated archive behind.
    """
    if not js:
        raise RuntimeError('no CVE data was fetched from any source; refusing to write')

    old_count = 0
    if os.path.isfile(filename):
        try:
            with gzip.open(filename, 'rt', encoding='utf-8') as fh:
                old_count = len(json.load(fh))
        except (OSError, ValueError):
            old_count = 0  # corrupt or unreadable: treat as absent
    if old_count and len(js) < 0.9 * old_count:
        raise RuntimeError(
            f'refusing to overwrite {filename}: the new set has {len(js)} CVEs '
            f'vs {old_count} existing (>10% shrink); write to a new path to override'
        )

    tmp = filename + '.tmp'
    try:
        with gzip.open(tmp, 'wt', encoding='utf-8') as fh:
            json.dump(js, fh)
        os.replace(tmp, filename)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print(f'Usage: {args[0]} <kernel_repo_dir> [metadata_file]', file=sys.stderr)
        sys.exit(1)
    repo = args[1]
    mainline = get_mainline_commit(repo)

    filename = None
    if len(args) == 3:
        filename = args[2]
    else:
        # Default to the working directory: the blob is no longer git-tracked
        # or rewritten inside the installed package; CI (or the maintainer)
        # publishes it as a content-latest release asset.
        filename = os.environ.get('CVEHOUND_METADATA', 'kernel_cves.json.gz')

    # Keep the clones in the user cache: the metadata file usually lives inside
    # the installed package, which is no place for a couple of git repositories.
    cache_dir = get_cache_dir()
    os.makedirs(cache_dir, exist_ok=True)

    print('Fetching exploit status from CISA KEV...')
    exploited_cves = get_exploit_status_from_cisa_kev()
    print(f'Found {len(exploited_cves)} known exploited CVEs from CISA KEV')

    print('Fetching CVE data from kernel.org vulns.git...')
    kernel_vulns_cves = fetch_kernel_vulns_data(cache_dir, repo, mainline)
    print(f'Found {len(kernel_vulns_cves)} CVEs from kernel.org vulns.git')

    print('Fetching CVE data from CIP kernel-sec...')
    cip_cves = fetch_cip_kernel_sec_data(cache_dir, repo, mainline)
    print(f'Found {len(cip_cves)} CVEs from CIP kernel-sec')

    print('Merging CVE data...')
    js = merge_cve_data(kernel_vulns_cves, cip_cves)
    print(f'Total unique CVEs: {len(js)}')

    print('Enriching CVE data with fix dates and exploit status...')
    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix:
            commit = get_commit_info(repo, fix)
            if commit:
                info['fix_date'] = commit[0]
                # Always derive the subject from the commit selected above. CNA
                # titles and cached metadata can describe a different fix in a
                # multi-fix record.
                info['cmt_msg'] = commit[1]
        info['exploit'] = cve in exploited_cves
    js = {cve: dropempty(info) for cve, info in js.items()}

    print(f'Writing metadata to {filename}...')
    try:
        write_metadata(js, filename)
    except RuntimeError as err:
        print(f'Error: {err}', file=sys.stderr)
        sys.exit(1)

    print('Done!')


if __name__ == '__main__':
    main(sys.argv)
