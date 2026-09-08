"""What git history says about CVEs, without running a single rule.

Two questions. For a range: which known fix and introducing commits it
contains, and which fixes it carries as backports. For a finding: whether the
fix the rule looks for is already in the scanned history -- in which case the
rule firing is the interesting kind of finding, a backport that did not take
or a regression, rather than a fix nobody applied.

Both read commit messages, so they are only as good as the messages. Stable
backports cite their upstream commit in one of three spellings, all of which
say 'commit <sha>'; a 'Fixes: <sha>' trailer names the bug's origin, not a
carried fix, and is never read as one.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from cvehound import CVEhound
from cvehound.gitrepo import ABBREV, GitRepo

# "commit X upstream" (stable-queue), "[ Upstream commit X ]" (AUTOSEL),
# "(cherry picked from commit X)" (vendor trees).
UPSTREAM_CITE = re.compile(r'\bcommit\s+([0-9a-f]{12,40})\b', re.IGNORECASE)
FIXES_TRAILER = re.compile(r'^\s*Fixes:\s*([0-9a-f]{7,40})\b', re.IGNORECASE | re.MULTILINE)
REVERT_CITE = re.compile(r'This reverts commit\s+([0-9a-f]{12,40})\b', re.IGNORECASE)

# The shortest prefix a citation is matched on: what Fixes: trailers use.
PREFIX = ABBREV

# An introducing commit shared by more CVEs than this says nothing about which
# one a 'Fixes:' trailer means -- 1da177e4 (the initial import) is the bug's
# origin for hundreds of them.
MAX_SHARED_ORIGIN = 5


@dataclass
class RangeEvidence:
    """CVEs a set of commits speaks for, each mapped to the commits that do."""

    fixes: dict[str, list[str]] = field(default_factory=dict)
    introduces: dict[str, list[str]] = field(default_factory=dict)
    backports: dict[str, list[str]] = field(default_factory=dict)
    candidates: dict[str, list[str]] = field(default_factory=dict)

    def report(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        parts = []
        for singular, plural, table in (
            ('CVE fix', 'CVE fixes', self.fixes),
            ('introducing commit', 'introducing commits', self.introduces),
            ('backport', 'backports', self.backports),
            ('candidate fix', 'candidate fixes', self.candidates),
        ):
            if table:
                n = len(table)
                parts.append(f'{n} {singular if n == 1 else plural}')
        return ', '.join(parts) if parts else 'nothing known'


def commit_table(hound: CVEhound) -> dict[str, dict[str, str]]:
    """Fix and introducing commit per CVE: the metadata's, with a rule's own
    Fix:/Fixes: header on top.

    The header wins where both exist because it is what the rule was written
    and tested against, and a rule can exist for a CVE the metadata has no
    entry for at all.
    """
    table: dict[str, dict[str, str]] = {}
    for cve, info in hound.metadata.items():
        entry = {key: info[key] for key in ('fixes', 'breaks') if isinstance(info.get(key), str)}
        if entry:
            table[cve] = entry
    for cve in hound.get_all_cves():
        entry = table.setdefault(cve, {})
        fix, fixes = hound.get_rule_fix(cve), hound.get_rule_fixes(cve)
        if fix:
            entry['fixes'] = fix
        if fixes:
            entry['breaks'] = fixes
    return table


def _index(metadata: Mapping[str, Mapping[str, Any]], key: str) -> dict[str, list[str]]:
    """CVEs by the 12-hex prefix of their `key` commit."""
    index: dict[str, list[str]] = defaultdict(list)
    for cve, info in metadata.items():
        sha = info.get(key)
        if isinstance(sha, str) and len(sha) >= PREFIX:
            index[sha[:PREFIX].lower()].append(cve)
    return index


def range_evidence(
    commits: Iterable[tuple[str, str]], metadata: Mapping[str, Mapping[str, Any]]
) -> RangeEvidence:
    """Read (sha, message) pairs against the metadata's fix/introducing commits.

    A commit whose own sha is a known fix fixes that CVE; one whose sha is a
    known introducing commit introduces it; one citing a known fix as its
    upstream carries that fix; one whose Fixes: trailer names a known
    introducing commit is a candidate fix for the CVE -- candidate, because it
    fixes a bug from that commit, not necessarily the CVE's.
    """
    fixes_by = _index(metadata, 'fixes')
    breaks_by = _index(metadata, 'breaks')
    evidence = RangeEvidence()

    def add(table: dict[str, list[str]], cves: Iterable[str], sha: str) -> None:
        for cve in cves:
            entries = table.setdefault(cve, [])
            if sha not in entries:
                entries.append(sha)

    for sha, message in commits:
        prefix = sha[:PREFIX].lower()
        add(evidence.fixes, fixes_by.get(prefix, ()), sha)
        add(evidence.introduces, breaks_by.get(prefix, ()), sha)
        for cited in UPSTREAM_CITE.findall(message):
            add(evidence.backports, fixes_by.get(cited[:PREFIX].lower(), ()), sha)
        for cited in FIXES_TRAILER.findall(message):
            if len(cited) < PREFIX:
                continue
            origin = breaks_by.get(cited[:PREFIX].lower(), ())
            if 0 < len(origin) <= MAX_SHARED_ORIGIN:
                add(evidence.candidates, origin, sha)

    # A fix commit naming the bug's origin in its own Fixes: trailer is the
    # normal shape of a fix, not a second fact: what it does for the CVE is
    # already recorded. Only a commit that speaks for the CVE in no other way
    # stays a candidate.
    for cve, shas in list(evidence.candidates.items()):
        known = set(evidence.fixes.get(cve, ())) | set(evidence.backports.get(cve, ()))
        rest = [sha for sha in shas if sha not in known]
        if rest:
            evidence.candidates[cve] = rest
        else:
            del evidence.candidates[cve]
    return evidence


FIX_PRESENT = 'fix-present'
FIX_REVERTED = 'fix-reverted'
FIX_ABSENT = 'fix-absent'
UNKNOWN = 'unknown'


@dataclass(frozen=True)
class FixEvidence:
    """Where the fix a rule looks for stands in the scanned history."""

    fix: str
    in_history: bool | None
    backports: tuple[str, ...] = ()
    reverted_by: str | None = None

    @property
    def verdict(self) -> str:
        if self.reverted_by:
            return FIX_REVERTED
        if self.in_history or self.backports:
            return FIX_PRESENT
        if self.in_history is False:
            return FIX_ABSENT
        return UNKNOWN

    def report(self) -> dict[str, Any]:
        return {
            'fix': self.fix,
            'fix_in_history': self.in_history,
            'backports': list(self.backports),
            'reverted_by': self.reverted_by,
            'verdict': self.verdict,
        }

    def describe(self) -> str:
        """One line for a human: the verdict, and what it rests on."""
        verdict = self.verdict
        if self.reverted_by:
            return f'{verdict} (by {self.reverted_by[:12]})'
        if verdict == FIX_PRESENT:
            how = (
                f'backported as {", ".join(sha[:12] for sha in self.backports)}'
                if self.backports
                else f'in history as {self.fix[:12]}'
            )
            what = 'check the backport' if self.backports else 'check for a regression'
            return f'{verdict} ({how}) -- rule still fires, {what}'
        if verdict == FIX_ABSENT:
            return verdict
        return f'{verdict} (fix {self.fix[:12]} not in this repository)'


def fix_evidence(
    repo: GitRepo, sha: str, findings: Mapping[str, tuple[str, int | None]]
) -> dict[str, FixEvidence]:
    """For each finding (cve -> (fix sha, fix date or None)): is its fix in
    the history of `sha`, directly or as a backport, and was it reverted?

    One ancestry question per finding, then one walk of the history for all
    of them at once -- backports and reverts can only be found in messages,
    and that walk is bounded to commits since the oldest fix involved, since
    neither can predate what it carries.
    """
    if not findings:
        return {}
    ancestry = {cve: repo.is_ancestor(fix, sha) for cve, (fix, _) in findings.items()}
    needles = {fix[:PREFIX].lower(): cve for cve, (fix, _) in findings.items()}
    dates = [date for _, date in findings.values() if date]
    since = None
    if dates and len(dates) == len(findings):
        since = f'@{min(dates)}'
    backports: dict[str, list[str]] = defaultdict(list)
    reverted: dict[str, str] = {}
    for commit, message in repo.log_messages(sha, grep=needles, since=since, no_merges=True):
        for cited in REVERT_CITE.findall(message):
            cve = needles.get(cited[:PREFIX].lower())
            if cve and cve not in reverted:
                reverted[cve] = commit
        for cited in UPSTREAM_CITE.findall(message):
            cve = needles.get(cited[:PREFIX].lower())
            if cve and commit not in backports[cve] and commit != reverted.get(cve):
                backports[cve].append(commit)
    return {
        cve: FixEvidence(fix, ancestry[cve], tuple(backports.get(cve, ())), reverted.get(cve))
        for cve, (fix, _) in findings.items()
    }


def finding_fixes(hound: CVEhound, cves: Iterable[str]) -> dict[str, tuple[str, int | None]]:
    """The (fix sha, fix date) fix_evidence() wants, for the CVEs that have a fix on record."""
    table = commit_table(hound)
    findings = {}
    for cve in cves:
        fix = table.get(cve, {}).get('fixes')
        if fix and len(fix) >= PREFIX:
            date = hound.get_cve_metadata(cve).get('fix_date')
            findings[cve] = (fix, int(date) if isinstance(date, int | float) else None)
    return findings


def prune_unintroduced(
    repo: GitRepo, hound: CVEhound, cves: Iterable[str], sha: str
) -> tuple[list[str], dict[str, str]]:
    """Split CVEs into those whose introducing commit reaches `sha` (or is
    unknown here) and those it provably does not.

    Opt-in for a reason: a vendor tree that was rebased or squashed has no
    upstream commit in its ancestry, so on such a tree this prunes everything
    it can name. Nothing is pruned for a fix predating the revision: that is a
    finding, not noise. One walk of the history answers for every rule.
    """
    table = commit_table(hound)
    origins = {
        cve: origin
        for cve in cves
        if (origin := table.get(cve, {}).get('breaks')) and len(origin) >= PREFIX
    }
    wanted = {origin[:PREFIX].lower() for origin in origins.values()}
    reached = repo.reachable(sha, wanted) if wanted else set()
    kept: list[str] = []
    skipped: dict[str, str] = {}
    for cve in cves:
        origin = origins.get(cve)
        # Not reached is proof only when the commit exists here at all.
        if origin and origin[:PREFIX].lower() not in reached and repo.has_commit(origin):
            skipped[cve] = f'introducing commit {origin[:12]} is not in the history of {sha[:12]}'
        else:
            kept.append(cve)
    return kept, skipped
