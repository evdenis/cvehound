import conftest
from conftest import (
    INITIAL_COMMIT_HASH,
    KernelCheckout,
    _get_kernel_route,
    _reorder_kernel_tests,
)


class FakeGit:
    def __init__(self):
        self.calls = []

    def checkout(self, *args):
        self.calls.append(args)


class FakeRepo:
    def __init__(self):
        self.git = FakeGit()


class FakeMarker:
    def __init__(self, *args):
        self.args = args


class FakeCallSpec:
    def __init__(self, **params):
        self.params = params


class FakeItem:
    nodeid = 'fake-item'

    def __init__(self, route=None, skipped=False, **params):
        self.marker = FakeMarker(*route) if route is not None else None
        self.skipped = skipped
        self.callspec = FakeCallSpec(**params)

    def get_closest_marker(self, name):
        if name == 'kernel_history':
            return self.marker
        if name == 'skip' and self.skipped:
            return FakeMarker()
        return None


class FakeHound:
    def get_rule_fix(self, _cve):
        return 'fix'

    def get_rule_fixes(self, _cve):
        return INITIAL_COMMIT_HASH


def test_checkout_skips_clean_duplicate_and_invalidates_after_paths():
    repo = FakeRepo()
    checkout = KernelCheckout(repo)
    checkout.add_commits({'commit': 'oid', 'alias': 'oid'})

    checkout.checkout('commit')
    checkout.checkout('alias')
    checkout.checkout('other', ['file.c'])
    checkout.checkout('alias')

    assert repo.git.calls == [
        ('--force', 'commit'),
        ('--force', 'other', '--', ['file.c']),
        ('--force', 'alias'),
    ]


def test_reorder_kernel_tests_mixes_tests_and_preserves_skipped_slots(monkeypatch):
    metadata = FakeItem()
    older = FakeItem(('branch',), branch='older')
    skipped = FakeItem(('branch',), skipped=True, branch='missing')
    newer = FakeItem(('branch',), branch='newer')
    items = [metadata, older, skipped, newer]

    def resolve(refs):
        assert refs == ['older', 'newer']
        return {'older': 'old-oid', 'newer': 'new-oid'}

    monkeypatch.setattr(conftest, '_resolve_kernel_commits', resolve)
    monkeypatch.setattr(
        conftest,
        '_rank_kernel_commits',
        lambda _commits: {'new-oid': 0, 'old-oid': 1},
    )
    monkeypatch.setattr(conftest, '_kernel_checkout', KernelCheckout(FakeRepo()))

    _reorder_kernel_tests(items)

    assert items == [metadata, newer, skipped, older]


def test_get_kernel_route_omits_parent_of_initial_commit(monkeypatch):
    monkeypatch.setattr('conftest._cvehound', FakeHound())
    item = FakeItem(('fixes', 'fixes~'), cve='CVE-TEST')

    assert _get_kernel_route(item) == (INITIAL_COMMIT_HASH,)


def test_get_kernel_route_uses_selected_branch():
    item = FakeItem(('branch',), branch='stable/linux-6.6.y', cve='CVE-TEST')

    assert _get_kernel_route(item) == ('stable/linux-6.6.y',)
