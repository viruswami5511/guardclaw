"""
guardclaw/core/failure.py  --  GEF Failure Classification v1.1.0

LOCKED taxonomy after v1.0.0. Level 1 (FailureType) strings are permanent API contract.

v1.1.0 additions (Phase 2 trust layer):
    + IDENTITY_VIOLATION (new FailureType)
    + UNKNOWN_KEY_ID, REVOKED_KEY, KEY_ID_MISMATCH (new FailureDetail)

CRITICAL RULES:
    failure_sequence = line_num ALWAYS (0-indexed physical file position).
    NEVER entry.sequence -- that is attacker-controlled data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from guardclaw.core.canonical import canonical_json_encode


class FailureType:
    """Level 1 constants. PERMANENT. Never rename, never remove."""
    LEDGER_INVALID              = "ledger_invalid"
    MALFORMED_JSON              = "malformed_json"
    SCHEMA_VIOLATION            = "schema_violation"
    SIGNATURE_ENCODING_INVALID  = "signature_encoding_invalid"
    SIGNATURE_INVALID           = "signature_invalid"
    CHAIN_VIOLATION             = "chain_violation"
    DUPLICATE_RECORD_ID         = "duplicate_record_id"
    SIGNER_MISMATCH             = "signer_mismatch"
    IDENTITY_VIOLATION          = "identity_violation"   # Phase 2: trust layer

    ALL: frozenset = frozenset({
        "ledger_invalid",
        "malformed_json",
        "schema_violation",
        "signature_encoding_invalid",
        "signature_invalid",
        "chain_violation",
        "duplicate_record_id",
        "signer_mismatch",
        "identity_violation",
    })


class FailureDetail:
    """
    Level 2 detail strings.
    Machine-readable codes used in VerificationSummary.failure_detail.
    """
    # MALFORMED_JSON
    JSON_DECODE_ERROR           = "json_decode_error"

    # SCHEMA_VIOLATION
    MISSING_SIGNATURE           = "missing_signature"
    RECORD_TOO_LARGE            = "record_too_large"

    # SIGNATURE_ENCODING_INVALID
    INVALID_BASE64URL           = "invalid_base64url"

    # SIGNATURE_INVALID
    ED25519_FAILED              = "ed25519_verification_failed"

    # CHAIN_VIOLATION
    GENESIS_MISSING             = "genesis_missing"
    DUPLICATE_GENESIS           = "duplicate_genesis"
    SEQUENCE_GAP                = "sequence_gap"
    GEF_VERSION_MISMATCH        = "gef_version_mismatch"
    CAUSAL_HASH_MISMATCH        = "causal_hash_mismatch"
    DUPLICATE_NONCE             = "duplicate_nonce"
    POST_INTERRUPTED_RECORD     = "post_interrupted_record"
    SESSION_ID_MISMATCH         = "session_id_mismatch"
    SIGNER_MISMATCH             = "signer_mismatch"

    # LEDGER_INVALID (pre-flight)
    FILE_NOT_FOUND              = "file_not_found"
    EMPTY_LEDGER                = "empty_ledger"

    # IDENTITY_VIOLATION (Phase 2 trust layer)
    UNKNOWN_KEY_ID              = "unknown_key_id"
    REVOKED_KEY                 = "revoked_key"
    KEY_ID_MISMATCH             = "key_id_mismatch"

    @staticmethod
    def missing_field(fieldname: str) -> str:
        return f"missing_field_{fieldname}"


class ProtocolInvariantError(Exception):
    """Raised when VerificationSummary is constructed in an invalid state."""


@dataclass
class VerificationSummary:
    """Final contract for ledger verification results."""
    total_entries: int
    chain_valid: bool
    interrupted: bool = False
    verification_level: str = "EMPTY"

    recovery_mode_active: bool = False
    verified_count: int = 0
    valid_signatures: int = 0
    invalid_signatures: int = 0

    failure_sequence: Optional[int] = None
    failure_type: Optional[str] = None
    failure_detail: Optional[str] = None

    integrity_boundary_hash: Optional[str] = None
    boundary_sequence: Optional[int] = None

    # Phase 2: identity enforcement metadata
    identity_enforced: bool = False

    def __post_init__(self) -> None:
        if self.total_entries == 0:
            self.verification_level = "EMPTY"
        elif self.chain_valid and not self.interrupted:
            self.verification_level = "FULLY_VALID"
        elif self.chain_valid and self.interrupted:
            self.verification_level = "FULLY_VALID_INTERRUPTED"
        elif not self.chain_valid and self.verified_count > 0 and self.recovery_mode_active:
            self.verification_level = "PARTIALLY_VALID"
        else:
            self.verification_level = "INVALID"

        if self.verification_level == "PARTIALLY_VALID" and not self.recovery_mode_active:
            raise ProtocolInvariantError(
                "Contradiction: PARTIALLY_VALID requires recovery_mode_active=True."
            )
        if not self.chain_valid and self.failure_type is None:
            raise ProtocolInvariantError(
                "Invariant Violation: chain_valid=False requires failure_type to be set."
            )
        if (
            self.failure_type == FailureType.LEDGER_INVALID
            and self.failure_detail in (FailureDetail.FILE_NOT_FOUND, FailureDetail.EMPTY_LEDGER)
            and self.integrity_boundary_hash is not None
        ):
            raise ProtocolInvariantError(
                "Invariant Violation: Pre-flight failures cannot have an integrity_boundary_hash."
            )

    def to_dict(self) -> dict:
        return {
            "chain_valid": self.chain_valid,
            "interrupted": self.interrupted,
            "verification_level": self.verification_level,
            "total_entries": self.total_entries,
            "valid_signatures": self.valid_signatures,
            "invalid_signatures": self.invalid_signatures,
            "verified_count": self.verified_count,
            "failure_sequence": self.failure_sequence,
            "failure_type": self.failure_type,
            "failure_detail": self.failure_detail,
            "recovery_mode_active": self.recovery_mode_active,
            "identity_enforced": self.identity_enforced,
        }


def compute_boundary_hash(entry) -> str:
    """SHA-256(canonical_json(entry.to_signing_dict())). Locked formula."""
    return hashlib.sha256(
        canonical_json_encode(entry.to_signing_dict())
    ).hexdigest()


def first_schema_error(errors: list[str]) -> str:
    if not errors:
        return "unknown_schema_error"
    return sorted(errors)[0]