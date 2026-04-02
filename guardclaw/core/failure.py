"""
guardclaw/core/failure.py  —  GEF Failure Classification v0.7.2

LOCKED after v0.7.2. Level 1 (FailureType) strings are permanent API contract.

CRITICAL RULES:
    failure_sequence = line_num ALWAYS (0-indexed physical file position)
    NEVER entry.sequence — that is attacker-controlled data.

    missing_field format  = "missing_field:<exact_gef_key_name>"
    file_not_found        = FailureDetail.FILE_NOT_FOUND   (pre-flight: file missing)
    empty_ledger          = FailureDetail.EMPTY_LEDGER     (pre-flight: file empty)
    genesis_missing       = FailureDetail.GENESIS_MISSING  (runtime: first entry != GENESIS)

FIELD SEMANTICS (locked):
    failure_sequence  = physical file line_num (0-indexed, truth source)
    total_entries     = number of non-empty ledger entries processed
    verified_count    = trusted prefix (entries that passed all checks)

INVARIANTS (enforced in VerificationSummary.__post_init__):
    1. recovery_mode_active=True AND chain_valid=True AND partial_integrity=True → contradiction
    2. chain_valid=False → failure_type MUST be set
    3. pre-flight LEDGER_INVALID (FILE_NOT_FOUND / EMPTY_LEDGER) → integrity_boundary_hash MUST be None
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from guardclaw.core.canonical import canonical_json_encode


class FailureType:
    """Level 1 constants. PERMANENT after v0.7.2. Never rename, never remove."""
    LEDGER_INVALID             = "ledger_invalid"
    MALFORMED_JSON             = "malformed_json"
    SCHEMA_VIOLATION           = "schema_violation"
    SIGNATURE_ENCODING_INVALID = "signature_encoding_invalid"
    SIGNATURE_INVALID          = "signature_invalid"
    CHAIN_VIOLATION            = "chain_violation"

    ALL: frozenset = frozenset({
        "ledger_invalid", "malformed_json", "schema_violation",
        "signature_encoding_invalid", "signature_invalid", "chain_violation",
    })


class FailureDetail:
    """
    Level 2 detail strings. Flexible — can evolve between minor versions.
    Use missing_field() for missing GEF schema keys.
    """
    # MALFORMED_JSON
    JSON_DECODE_ERROR           = "json_decode_error"

    # SCHEMA_VIOLATION
    MISSING_SIGNATURE           = "missing_signature"
    INVALID_GEF_VERSION         = "invalid_gef_version"
    INVALID_RECORD_TYPE         = "invalid_record_type"
    INVALID_RECORD_ID           = "invalid_record_id"
    INVALID_AGENT_ID            = "invalid_agent_id"
    INVALID_PUBLIC_KEY          = "invalid_public_key"
    INVALID_NONCE               = "invalid_nonce"
    INVALID_TIMESTAMP           = "invalid_timestamp"
    INVALID_CAUSAL_HASH_FORMAT  = "invalid_causal_hash_format"
    INVALID_SEQUENCE_FORMAT     = "invalid_sequence_format"
    INVALID_PAYLOAD             = "invalid_payload"

    # SIGNATURE_ENCODING_INVALID
    INVALID_BASE64URL           = "invalid_base64url_encoding"

    # SIGNATURE_INVALID
    ED25519_FAILED              = "ed25519_verification_failed"

    # CHAIN_VIOLATION
    SEQUENCE_GAP                = "sequence_gap"
    SEQUENCE_DUPLICATE          = "sequence_duplicate"
    GEF_VERSION_MISMATCH        = "gef_version_mismatch"
    CAUSAL_HASH_MISMATCH        = "causal_hash_mismatch"
    MIXED_AGENT_ID              = "mixed_agent_id"
    DUPLICATE_NONCE             = "duplicate_nonce"
    SEQUENCE_ORDER              = "sequence_order"
    GENESIS_MISSING             = "genesis_missing"     # runtime: first entry != GENESIS record_type

    # LEDGER_INVALID — pre-flight only (file system / structural)
    FILE_NOT_FOUND              = "file_not_found"
    EMPTY_LEDGER                = "empty_ledger"

    @staticmethod
    def missing_field(field_name: str) -> str:
        """
        Returns "missing_field:<field_name>".
        field_name MUST match exact GEF schema key (case-sensitive).
        """
        return f"missing_field:{field_name}"


class ProtocolInvariantError(Exception):
    """Raised when VerificationSummary is constructed in an invalid state."""
    pass


@dataclass
class VerificationSummary:
    """
    Result of ReplayEngine.stream_verify().

    Strict mode:   chain_valid=True/False. recovery_mode_active=False.
    Recovery mode: recovery_mode_active=True always (mode != outcome).
                   partial_integrity=True only if prefix was certified before failure.

    Field semantics (locked v0.7.2):
        total_entries     = number of non-empty ledger entries processed
        verified_count    = entries that passed all checks (trusted prefix)
        failure_sequence  = physical file line_num (0-indexed, NOT entry.sequence)
    """
    # Always present
    total_entries: int    # number of non-empty ledger entries processed

    chain_valid:   bool

    # Mode flag — True whenever engine.mode == "recovery"
    recovery_mode_active:    bool          = False

    # Recovery outcome fields
    partial_integrity:       bool          = False
    verified_count:          int           = 0      # entries that passed all checks
    failure_sequence:        Optional[int] = None   # line_num 0-indexed, NOT entry.sequence
    failure_type:            Optional[str] = None   # FailureType Level 1
    failure_detail:          Optional[str] = None   # FailureDetail Level 2
    integrity_boundary_hash: Optional[str] = None   # SHA-256(JCS(last_valid.to_signing_dict()))
    boundary_sequence:       Optional[int] = None   # last_valid.sequence (logical ref only)

    def __post_init__(self) -> None:
        # Invariant 1
        if self.recovery_mode_active and self.chain_valid and self.partial_integrity:
            raise ProtocolInvariantError(
                "Invariant 1 violated: recovery_mode_active=True with "
                "chain_valid=True AND partial_integrity=True is contradictory."
            )

        # Invariant 2
        if not self.chain_valid and self.failure_type is None:
            raise ProtocolInvariantError(
                "Invariant 2 violated: chain_valid=False requires failure_type to be set."
            )

        # Invariant 3: pre-flight LEDGER_INVALID cannot have boundary hash
        if (
            self.failure_type == FailureType.LEDGER_INVALID
            and self.failure_detail in (
                FailureDetail.FILE_NOT_FOUND,
                FailureDetail.EMPTY_LEDGER,
            )
            and self.integrity_boundary_hash is not None
        ):
            raise ProtocolInvariantError(
                "Invariant 3 violated: pre-flight LEDGER_INVALID "
                "cannot have integrity_boundary_hash."
            )

    def to_dict(self) -> dict:
        return {
            "chain_valid":               self.chain_valid,
            "total_entries":             self.total_entries,
            "recovery_mode_active":      self.recovery_mode_active,
            "partial_integrity":         self.partial_integrity,
            "verified_count":            self.verified_count,
            "failure_sequence":          self.failure_sequence,
            "failure_type":              self.failure_type,
            "failure_detail":            self.failure_detail,
            "integrity_boundary_hash":   self.integrity_boundary_hash,
            "boundary_sequence":         self.boundary_sequence,
        }


def compute_boundary_hash(entry) -> str:
    """
    SHA-256(RFC 8785 JCS(entry.to_signing_dict())).
    Locked formula. Reproducible by any independent implementation.
    Returns 64-char lowercase hex digest.
    """
    return hashlib.sha256(
        canonical_json_encode(entry.to_signing_dict())
    ).hexdigest()


def first_schema_error(errors: list) -> str:
    """sorted(errors)[0] — deterministic, same input always gives same output."""
    if not errors:
        return "unknown_schema_error"
    return sorted(errors)[0]