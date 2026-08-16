#!/usr/bin/env python3

import glob
import gzip
import json
import os
import re
import ssl
import subprocess
import sys
from importlib.resources import files
from io import BytesIO
from typing import Any
from urllib.request import Request, urlopen
from zipfile import ZipFile

import lxml.etree as etree  # ty: ignore[unresolved-import]
import yaml

KERNEL_VULNS_REPO = 'https://git.kernel.org/pub/scm/linux/security/vulns.git'
CIP_KERNEL_SEC_REPO = 'https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec.git'
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


def get_exploit_status_from_fstec() -> tuple[set[str], set[str]]:
    """Fetch exploit status from the FSTEC database."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = Request(
        'https://bdu.fstec.ru/files/documents/vulxml.zip', headers={'User-Agent': 'Mozilla/5.0'}
    )
    with (
        urlopen(req, context=ctx) as uh,
        ZipFile(BytesIO(uh.read())) as zh,
        zh.open('export/export.xml') as fh,
    ):
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(fh, parser)

    public: set[str] = set()
    private: set[str] = set()
    for item in tree.xpath('//vul'):
        item.xpath('identifier/text()')[0]
        cve_id: str | None = None
        for vuln_id in item.xpath('identifiers/identifier'):
            if vuln_id.get('type') == 'CVE':
                cve_id = vuln_id.text
                break
        is_linux = False
        for name in item.xpath('vulnerable_software/soft/name/text()'):
            if name == 'Linux' or name == 'linux':
                is_linux = True
        if not is_linux:
            continue
        if not cve_id:
            continue

        exploit_status = item.xpath('exploit_status/text()')[0]
        if 'открыт' in exploit_status:  # 'открытом' == 'public'
            public.add(cve_id)
        elif 'уществует' in exploit_status:  # == exists
            private.add(cve_id)

    return public, private


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


def parse_kernel_vulns_cve(cve_file: str) -> tuple[str | None, dict[str, Any] | None]:
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

    # Every branch that carries the fix is listed as its own git range, with the
    # mainline one last; all the earlier entries are stable backports that do not
    # exist in mainline history. The 'version' of a range is the commit that
    # introduced the bug, the 'lessThan' is the commit that fixed it. Ranges
    # without a 'lessThan' are branches that are still unfixed.
    ranges = [
        version
        for item in cna.get('affected', [])
        for version in item.get('versions', [])
        if version.get('versionType') == 'git'
        and version.get('status') == 'affected'
        and version.get('lessThan')
    ]

    # cna.title is the subject line of the fixing commit
    info: dict[str, Any] = {'cmt_msg': cna.get('title', '')}
    if ranges:
        info['fixes'] = get_commit_id(ranges[-1]['lessThan'])
        info['breaks'] = get_commit_id(ranges[-1].get('version'))

    return cve_id, dropempty(info)


def parse_cip_kernel_sec_cve(cve_file: str) -> tuple[str | None, dict[str, Any] | None]:
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
    for key, field in (('fixed-by', 'fixes'), ('introduced-by', 'breaks')):
        commits = (data.get(key) or {}).get('mainline')
        if isinstance(commits, str):
            commits = [commits]
        if commits:
            info[field] = get_commit_id(commits[0])

    if is_cip_rejected(data):
        info['rejected'] = True

    return cve_id, dropempty(info)


def fetch_kernel_vulns_data(temp_dir: str) -> dict[str, dict[str, Any]]:
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
                cve_id, info = parse_kernel_vulns_cve(cve_file)
                if cve_id and info:
                    if state == 'rejected':
                        info['rejected'] = True
                    cves[cve_id] = info
            except Exception as e:
                print(f'Warning: Failed to parse {cve_file}: {e}', file=sys.stderr)

    return cves


def fetch_cip_kernel_sec_data(temp_dir: str) -> dict[str, dict[str, Any]]:
    """Fetch CVE data from the CIP kernel-sec GitLab repository."""
    cip_dir = os.path.join(temp_dir, 'cip-kernel-sec')
    cves: dict[str, dict[str, Any]] = {}

    if clone_or_update_repo(CIP_KERNEL_SEC_REPO, cip_dir):
        cve_pattern = os.path.join(cip_dir, 'issues', 'CVE-*.yml')
        for cve_file in glob.glob(cve_pattern):
            try:
                cve_id, info = parse_cip_kernel_sec_cve(cve_file)
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


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print(f'Usage: {args[0]} <kernel_repo_dir> [metadata_file]', file=sys.stderr)
        sys.exit(1)
    repo = args[1]

    filename = None
    if len(args) == 3:
        filename = args[2]
    else:
        filename = os.environ.get(
            'CVEHOUND_METADATA', str(files('cvehound').joinpath('data/kernel_cves.json.gz'))
        )

    # Keep the clones in the user cache: the metadata file usually lives inside
    # the installed package, which is no place for a couple of git repositories.
    cache_dir = get_cache_dir()
    os.makedirs(cache_dir, exist_ok=True)

    previous: dict[str, dict[str, Any]] = {}
    if os.path.isfile(filename):
        with gzip.open(filename, 'rt', encoding='utf-8') as fh:
            previous = json.load(fh)

    print('Fetching exploit status from FSTEC...')
    try:
        public, private = get_exploit_status_from_fstec()
    except Exception as e:
        print(f'Warning: Failed to fetch FSTEC data: {e}', file=sys.stderr)
        public, private = set(), set()

    print('Fetching CVE data from kernel.org vulns.git...')
    kernel_vulns_cves = fetch_kernel_vulns_data(cache_dir)
    print(f'Found {len(kernel_vulns_cves)} CVEs from kernel.org vulns.git')

    print('Fetching CVE data from CIP kernel-sec...')
    cip_cves = fetch_cip_kernel_sec_data(cache_dir)
    print(f'Found {len(cip_cves)} CVEs from CIP kernel-sec')

    print('Merging CVE data...')
    js = merge_cve_data(kernel_vulns_cves, cip_cves)
    print(f'Total unique CVEs: {len(js)}')

    print('Enriching CVE data with fix dates and exploit status...')
    for cve, info in js.items():
        fix = info.get('fixes', '')
        old = previous.get(cve, {})
        if fix and old.get('fixes') == fix and 'fix_date' in old:
            # Nothing about the fix moved, so there is no need to ask git again
            info['fix_date'] = old['fix_date']
            info.setdefault('cmt_msg', old.get('cmt_msg', ''))
        elif fix:
            commit = get_commit_info(repo, fix)
            if commit:
                info['fix_date'] = commit[0]
                # CIP does not record the commit subject, so take it from the tree
                info.setdefault('cmt_msg', commit[1])
        info['exploit'] = cve in public or cve in private
    js = {cve: dropempty(info) for cve, info in js.items()}

    print(f'Writing metadata to {filename}...')
    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

    print('Done!')


if __name__ == '__main__':
    main(sys.argv)
