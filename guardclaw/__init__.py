"""
guardclaw/__init__.py

GuardClaw: Cryptographic Evidence Ledger for Autonomous Agent Accountability

GEF v1.0 - GuardClaw Evidence Format
"""

__version__     = "0.6.5"
__gef_version__ = "1.0"

from guardclaw.core.models import (
    ExecutionEnvelope,
    GEF_VERSION,
    GENESIS_HASH,
    RecordType,
    SchemaValidationResult,
    GEFVersionError,
)
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.emitter import (
    init_global_ledger,
    get_global_ledger,
    has_global_ledger,       # FIX: was missing — required by trace.py
    set_global_ledger,
)
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.time import gef_timestamp
from guardclaw.api import GEFSession, session, record_action, verify_ledger
from guardclaw.trace import trace

__all__ = [
    # Core types
    "ExecutionEnvelope",
    "GEFLedger",
    "Ed25519KeyManager",
    "RecordType",
    "SchemaValidationResult",
    "GEFVersionError",
    # Ledger lifecycle
    "init_global_ledger",
    "get_global_ledger",
    "has_global_ledger",
    "set_global_ledger",
    # Session API
    "GEFSession",
    "session",
    # Trace decorator (zero-friction entry point)
    "trace",
    # Legacy / adapter
    "record_action",
    "verify_ledger",
    # Utilities
    "canonical_json_encode",
    "gef_timestamp",
    # Constants
    "GEF_VERSION",
    "GENESIS_HASH",
]