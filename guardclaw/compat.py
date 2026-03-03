"""
guardclaw/compat.py

DEPRECATED - Phase 1 compatibility layer. Not part of GEF-SPEC-1.0.
This module is retained only to prevent ImportError on old installs.
All classes here are non-functional stubs.
Do not use in new code.
"""

import warnings

warnings.warn(
    "guardclaw.compat is a deprecated Phase 1 module and will be removed in v0.6.0. "
    "Use guardclaw.GEFLedger and guardclaw.core.models instead.",
    DeprecationWarning,
    stacklevel=2,
)
