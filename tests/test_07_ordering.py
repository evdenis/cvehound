import pytest
from conftest import (
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


def test_checkout_skips_clean_duplicate():
    repo = FakeRepo()
    checkout = KernelCheckout(repo)

    checkout.checkout('commit')
    checkout.checkout('commit')
    checkout.checkout('other')
    checkout.checkout('commit')

    assert repo.git.calls == [
        ('--force', 'commit'),
        ('--force', 'other'),
        ('--force', 'commit'),
    ]


def test_reorder_groups_by_branch_and_preserves_skipped_slots():
    metadata = FakeItem()
    second_b = FakeItem(('branch',), branch='b')
    skipped = FakeItem(('branch',), skipped=True, branch='missing')
    first_a = FakeItem(('branch',), branch='a')
    second_a = FakeItem(('branch',), branch='a')
    items = [metadata, second_b, skipped, first_a, second_a]

    _reorder_kernel_tests(items)

    assert items == [metadata, first_a, skipped, second_a, second_b]


def test_get_kernel_route_uses_selected_branch():
    item = FakeItem(('branch',), branch='stable/linux-6.6.y', cve='CVE-TEST')

    assert _get_kernel_route(item) == ('stable/linux-6.6.y',)


def test_get_kernel_route_rejects_retired_steps():
    item = FakeItem(('fixes', 'fixes~'), cve='CVE-TEST')

    with pytest.raises(pytest.UsageError):
        _get_kernel_route(item)
