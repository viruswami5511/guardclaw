"""
guardclaw/__init__.py

GuardClaw: Cryptographic Evidence Ledger for Autonomous Agent Accountability

GEF v1.0 — GuardClaw Evidence Format
...
v0.5.1 is the current GEF-SPEC-1.0 reference implementation.
All 0.1.x APIs are deprecated. Migration: replace EvidenceEmitter
with GEFLedger and Observer.on_* with ledger.emit().
"""

__version__     = "0.5.1"
__gef_version__ = "1.0"

from guardclaw.core.models import (
    ExecutionEnvelope,
    GEF_VERSION,
    GENESIS_HASH,
    RecordType,
    SchemaValidationResult,
    GEFVersionError,
)
from guardclaw.core.emitter import (
    GEFLedger,
    init_global_ledger,
    get_global_ledger,
)
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.time import gef_timestamp

__all__ = [
    # Core GEF types
    "ExecutionEnvelope",
    "GEFLedger",
    "Ed25519KeyManager",
    "RecordType",
    "SchemaValidationResult",
    # Errors
    "GEFVersionError",
    # Helpers
    "init_global_ledger",
    "get_global_ledger",
    "canonical_json_encode",
    "gef_timestamp",
    # Constants
    "GEF_VERSION",
    "GENESIS_HASH",
]
