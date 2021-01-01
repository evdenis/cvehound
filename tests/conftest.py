#!/usr/bin/env python3

import pytest
from cvehound import get_all_cves

def pytest_addoption(parser):
    parser.addoption(
        '--cve',
        action='append',
        default=[],
        help='list of CVEs',
    )

def pytest_generate_tests(metafunc):
    if 'cve' in metafunc.fixturenames:
        cves = metafunc.config.getoption('cve')
        if not cves:
            cves = get_all_cves()
        metafunc.parametrize('cve', cves)
