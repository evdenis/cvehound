#!/usr/bin/env python3

"""A zygote fault must not become the rule's verdict.

The fork server dies on some whole-tree scans (the child segfaults in OCaml's
unmarshaller); the identical scan run as a plain exec answers normally. Losing
the request would mark a valid rule not-strong for a reason that has nothing to
do with the rule, so an inferred zygote degrades to one spatch per rule. A
demanded one still fails loudly.
"""

import pytest

import cvehound
from cvehound import spatch_zygote
from cvehound.exception import SpatchError, SpatchTimeout


@pytest.fixture
def transports(monkeypatch):
    """Record which transport ran; the zygote always dies."""
    calls = []

    def dead_zygote(cmd, env, workdir, wall_timeout, degrade=True):
        calls.append('zygote')
        raise spatch_zygote.ZygoteDied('server exited mid-request')

    def exec_spatch(cmd, env, wall_timeout):
        calls.append('exec')
        return 0, 'stdout from the fallback', ''

    monkeypatch.setattr(spatch_zygote, 'run', dead_zygote)
    monkeypatch.setattr(cvehound, '_exec_spatch', exec_spatch)
    return calls


def test_died_zygote_falls_back(transports):
    out = cvehound._run_spatch('CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True)
    assert out == 'stdout from the fallback'
    assert transports == ['zygote', 'exec']


def test_demanded_zygote_still_fails(transports):
    with pytest.raises(SpatchError):
        cvehound._run_spatch(
            'CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True, demanded=True
        )
    assert transports == ['zygote'], 'a demanded zygote must not degrade silently'


@pytest.mark.parametrize(
    'rc, what', [(-11, 'SIGSEGV in the forked child'), (2, 'uncaught OCaml exception')]
)
def test_failed_child_falls_back(monkeypatch, rc, what):
    """The server survives, so only the return status says the request failed."""
    calls = []

    def crashing_child(cmd, env, workdir, wall_timeout, degrade=True):
        calls.append('zygote')
        return rc, '', ''  # the server is fine; this request is not

    def exec_spatch(cmd, env, wall_timeout):
        calls.append('exec')
        return 0, 'stdout from the fallback', ''

    monkeypatch.setattr(spatch_zygote, 'run', crashing_child)
    monkeypatch.setattr(cvehound, '_exec_spatch', exec_spatch)
    out = cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=True)
    assert out == 'stdout from the fallback', what
    assert calls == ['zygote', 'exec']


def test_second_failure_is_the_rule(monkeypatch):
    """One retry, not a loop: a fallback that also fails is the rule's verdict."""
    monkeypatch.setattr(spatch_zygote, 'run', lambda *a, **k: (2, '', 'boom'))
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: (2, '', 'boom again'))
    with pytest.raises(SpatchError):
        cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=True)


def test_failure_on_the_stock_transport_is_an_error(monkeypatch):
    """Without the zygote a crash is spatch's own, not a transport fault."""
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: (-11, '', 'boom'))
    with pytest.raises(SpatchError):
        cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=False)


def test_fallback_timeout_is_classified(monkeypatch):
    """A timeout in the fallback is a timeout, not a bare TimeoutError."""

    def dead_zygote(cmd, env, workdir, wall_timeout, degrade=True):
        raise spatch_zygote.ZygoteDied('server exited mid-request')

    def slow_exec(cmd, env, wall_timeout):
        raise TimeoutError('killed at the wall')

    monkeypatch.setattr(spatch_zygote, 'run', dead_zygote)
    monkeypatch.setattr(cvehound, '_exec_spatch', slow_exec)
    with pytest.raises(SpatchTimeout):
        cvehound._run_spatch('CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True)
