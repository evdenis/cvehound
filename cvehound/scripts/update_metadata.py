#!/usr/bin/env python3

import os
import sys
import gzip
import json
import subprocess
import glob
from urllib.request import urlopen, Request
from importlib.resources import files

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

KERNEL_VULNS_REPO = 'https://git.kernel.org/pub/scm/linux/security/vulns.git'
CIP_KERNEL_SEC_REPO = 'https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec.git'
# Using GitHub mirror of CISA KEV data for better reliability
CISA_KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'

def get_exploit_status_from_cisa_kev():
    """Fetch exploit status from CISA Known Exploited Vulnerabilities catalog."""
    exploited_cves = set()

    try:
        req = Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))

        # CISA KEV format has vulnerabilities in a list
        vulnerabilities = data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            if cve_id:
                exploited_cves.add(cve_id)

    except Exception as e:
        print(f"Warning: Failed to fetch CISA KEV data: {e}", file=sys.stderr)

    return exploited_cves

def get_commit_date(repo, commit):
    """Get the date of a commit from a git repository."""
    try:
        return int(subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', commit],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        ).strip())
    except Exception:
        return None

def clone_or_update_repo(url, path, depth=1):
    """Clone a git repository or update it if it already exists."""
    if os.path.isdir(os.path.join(path, '.git')):
        print(f"Updating {path}...")
        try:
            subprocess.check_call(['git', 'pull'], cwd=path,
                                stderr=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"Warning: Failed to update {path}", file=sys.stderr)
            return False
    else:
        print(f"Cloning {url}...")
        os.makedirs(path, exist_ok=True)
        try:
            subprocess.check_call(['git', 'clone', '--depth', str(depth), url, path],
                                stderr=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to clone {url}: {e}", file=sys.stderr)
            return False
    return True

def parse_kernel_vulns_cve(cve_file):
    """Parse a CVE from kernel.org vulns.git JSON format."""
    with open(cve_file, 'r') as f:
        data = json.load(f)

    cve_id = data.get('cveMetadata', {}).get('cveID', '')
    if not cve_id:
        return None, None

    cna = data.get('containers', {}).get('cna', {})
    description = cna.get('title', '')

    # Extract fix commits from affected versions
    fixes = []
    affected = cna.get('affected', [])
    for item in affected:
        versions = item.get('versions', [])
        for version in versions:
            if version.get('status') == 'affected' and 'lessThan' in version:
                fix = version['lessThan']
                if fix and fix not in fixes:
                    fixes.append(fix)

    info = {
        'description': description,
        'fixes': fixes[0] if fixes else '',
    }

    return cve_id, info

def parse_cip_kernel_sec_cve(cve_file):
    """Parse a CVE from CIP kernel-sec YAML format."""
    with open(cve_file, 'r') as f:
        data = yaml.safe_load(f)

    if not data:
        return None, None

    cve_id = os.path.basename(cve_file).replace('.yml', '')

    description = data.get('description', '')

    # Extract fix commits
    fixed_by = data.get('fixed-by', {})
    mainline_fixes = fixed_by.get('mainline', [])

    # Handle different formats
    fixes = ''
    if mainline_fixes:
        if isinstance(mainline_fixes, list) and len(mainline_fixes) > 0:
            fixes = mainline_fixes[0]
        elif isinstance(mainline_fixes, str):
            fixes = mainline_fixes

    info = {
        'description': description,
        'fixes': fixes,
    }

    return cve_id, info

def fetch_kernel_vulns_data(temp_dir):
    """Fetch CVE data from kernel.org vulns.git repository."""
    vulns_dir = os.path.join(temp_dir, 'kernel-vulns')
    cves = {}

    if clone_or_update_repo(KERNEL_VULNS_REPO, vulns_dir):
        # Find all CVE JSON files
        cve_pattern = os.path.join(vulns_dir, 'cve', 'published', '**', 'CVE-*.json')
        for cve_file in glob.glob(cve_pattern, recursive=True):
            try:
                cve_id, info = parse_kernel_vulns_cve(cve_file)
                if cve_id and info:
                    cves[cve_id] = info
            except Exception as e:
                print(f"Warning: Failed to parse {cve_file}: {e}", file=sys.stderr)

    return cves

def fetch_cip_kernel_sec_data(temp_dir):
    """Fetch CVE data from CIP kernel-sec GitLab repository."""
    cip_dir = os.path.join(temp_dir, 'cip-kernel-sec')
    cves = {}

    if clone_or_update_repo(CIP_KERNEL_SEC_REPO, cip_dir):
        # Find all CVE YAML files
        cve_pattern = os.path.join(cip_dir, 'issues', 'CVE-*.yml')
        for cve_file in glob.glob(cve_pattern):
            try:
                cve_id, info = parse_cip_kernel_sec_cve(cve_file)
                if cve_id and info:
                    cves[cve_id] = info
            except Exception as e:
                print(f"Warning: Failed to parse {cve_file}: {e}", file=sys.stderr)

    return cves

def merge_cve_data(kernel_vulns_cves, cip_cves):
    """Merge CVE data from both sources, preferring kernel.org vulns.git for newer CVEs."""
    merged = {}

    # Start with CIP data (older CVEs)
    merged.update(cip_cves)

    # Override with kernel.org vulns data (newer CVEs)
    for cve_id, info in kernel_vulns_cves.items():
        if cve_id not in merged:
            merged[cve_id] = info
        else:
            # Merge: prefer non-empty fixes from kernel.org vulns
            if info.get('fixes') and not merged[cve_id].get('fixes'):
                merged[cve_id]['fixes'] = info['fixes']
            # Prefer non-empty description from kernel.org vulns
            if info.get('description') and not merged[cve_id].get('description'):
                merged[cve_id]['description'] = info['description']

    return merged

def main(args=sys.argv):
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print('Usage: {} <kernel_repo_dir> [metadata_file]'.format(args[0]), file=sys.stderr)
        sys.exit(1)
    repo = args[1]

    filename = None
    if len(args) == 3:
        filename = args[2]
    else:
        filename = os.environ.get('CVEHOUND_METADATA',
                                  str(files('cvehound').joinpath('data/kernel_cves.json.gz')))

    # Create temporary directory for repositories
    temp_dir = os.path.join(os.path.dirname(filename), '.cve_repos_cache')
    os.makedirs(temp_dir, exist_ok=True)

    print("Fetching exploit status from CISA KEV...")
    exploited_cves = get_exploit_status_from_cisa_kev()
    print(f"Found {len(exploited_cves)} known exploited CVEs from CISA KEV")

    print("Fetching CVE data from kernel.org vulns.git...")
    kernel_vulns_cves = fetch_kernel_vulns_data(temp_dir)
    print(f"Found {len(kernel_vulns_cves)} CVEs from kernel.org vulns.git")

    print("Fetching CVE data from CIP kernel-sec...")
    cip_cves = fetch_cip_kernel_sec_data(temp_dir)
    print(f"Found {len(cip_cves)} CVEs from CIP kernel-sec")

    print("Merging CVE data...")
    js = merge_cve_data(kernel_vulns_cves, cip_cves)
    print(f"Total unique CVEs: {len(js)}")

    # Enrich with fix dates and exploit status
    print("Enriching CVE data with fix dates and exploit status...")
    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix and repo:
            fix_date = get_commit_date(repo, fix)
            if fix_date:
                info['fix_date'] = fix_date
        info['exploit'] = cve in exploited_cves

    print(f"Writing metadata to {filename}...")
    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

    print("Done!")

if __name__ == '__main__':
    main(sys.argv)
