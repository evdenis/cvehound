"""Library form of the detection oracle the test suite runs on.

check_cve()'s verdict on a rule at a commit is a pure function of (rule bytes,
blob contents, spatch build, harness logic). These modules make that verdict
cheap to ask at scale -- mini-trees materialized straight from the object
database, verdicts memoized in a persistent cache -- without a checkout and
without pytest. The test suite consumes this same code, so an external
consumer (e.g. a rule-generation harness scoring candidate rules) cannot
drift from what `pytest --runslow` would say.
"""

from cvehound.oracle.kerneltree import (
    ALL_FILES_PATH,
    BlobMaterializer,
    cached_all_files_check,
    cached_check,
    hound_at,
    object_header,
    sig_has_rule_files,
)
from cvehound.oracle.resultcache import HARNESS_EPOCH, ResultCache, Sig, context_id

__all__ = [
    'ALL_FILES_PATH',
    'HARNESS_EPOCH',
    'BlobMaterializer',
    'ResultCache',
    'Sig',
    'cached_all_files_check',
    'cached_check',
    'context_id',
    'hound_at',
    'object_header',
    'sig_has_rule_files',
]
