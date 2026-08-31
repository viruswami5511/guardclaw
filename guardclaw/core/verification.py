"""
guardclaw/core/verification.py
GEF Verification — v1.1 HARDENED
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re

from guardclaw.core.models import ExecutionEnvelope, VALID_RECORD_TYPES


HEX_64 = re.compile(r"^[0-9a-f]{64}$")

# Single source of truth — derived from models.py, never duplicated
ALLOWED_TYPES = VALID_RECORD_TYPES


@dataclass
class VerificationResult:
    valid: bool
    record_type: str
    record_id: str
    reason: str = ""
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}
        now = datetime.now(timezone.utc)
        self.verified_at = (
            now.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{now.microsecond // 1000:03d}Z"
        )

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "record_type": self.record_type,
            "record_id": self.record_id,
            "reason": self.reason,
            "details": self.details,
            "verified_at": self.verified_at,
        }


class VerificationError(Exception):
    pass


def _schema_contract_ok(schema: Any) -> bool:
    return (
        hasattr(schema, "valid")
        and isinstance(schema.valid, bool)
        and hasattr(schema, "errors")
        and isinstance(schema.errors, list)
        and all(isinstance(e, str) for e in schema.errors)
    )


def _signature_contract_ok(sig_result: Any) -> bool:
    return (
        isinstance(sig_result, tuple)
        and len(sig_result) == 2
        and isinstance(sig_result[0], bool)
        and isinstance(sig_result[1], str)
    )


def _enforce_spec(env: ExecutionEnvelope) -> Optional[VerificationResult]:
    if env.record_type not in ALLOWED_TYPES:
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="invalid_record_type",
        )
    if (
        not isinstance(env.signer_public_key, str)
        or not HEX_64.fullmatch(env.signer_public_key)
    ):
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="invalid_public_key_format",
        )
    if not isinstance(env.payload, dict):
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="invalid_payload_type",
        )
    if not isinstance(env.signature, str) or not env.signature.strip():
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="invalid_signature_field",
        )
    return None


def verify_envelope(env: ExecutionEnvelope) -> VerificationResult:
    try:
        schema = env.validate_schema()
    except Exception:
        return VerificationResult(
            valid=False,
            record_type=getattr(env, "record_type", "unknown"),
            record_id=getattr(env, "record_id", "unknown"),
            reason="schema_validation_exception",
        )

    if not _schema_contract_ok(schema):
        return VerificationResult(
            valid=False,
            record_type="unknown",
            record_id="unknown",
            reason="invalid_schema_return_contract",
        )

    if not schema.valid:
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="schema_validation_failed",
            details={"errors": schema.errors},
        )

    spec_error = _enforce_spec(env)
    if spec_error:
        return spec_error

    try:
        sig_result = env.verify_signature()
    except Exception:
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="signature_verification_exception",
        )

    if not _signature_contract_ok(sig_result):
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="invalid_signature_return_contract",
        )

    sig_ok, sig_reason = sig_result

    if sig_ok is True:
        return VerificationResult(
            valid=True,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="signature_verified",
            details={
                "sequence": env.sequence,
                "agent_id": env.agent_id,
                "signer_public_key": env.signer_public_key,
                "timestamp": env.timestamp,
                "gef_version": env.gef_version,
            },
        )

    if sig_reason == "encoding":
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="signature_encoding_invalid",
        )

    if sig_reason == "mismatch":
        return VerificationResult(
            valid=False,
            record_type=env.record_type,
            record_id=env.record_id,
            reason="signature_mismatch",
        )

    return VerificationResult(
        valid=False,
        record_type=env.record_type,
        record_id=env.record_id,
        reason="invalid_signature_reason_contract",
    )


def verify_envelope_from_dict(data: Dict[str, Any]) -> VerificationResult:
    try:
        env = ExecutionEnvelope.from_dict(data)
    except KeyError as exc:
        field = str(exc).strip("'\"")
        return VerificationResult(
            valid=False,
            record_type=data.get("record_type", "unknown"),
            record_id=data.get("record_id", "unknown"),
            reason="schema_violation",
            details={"missing_field": field},
        )
    except Exception as exc:
        return VerificationResult(
            valid=False,
            record_type=data.get("record_type", "unknown"),
            record_id=data.get("record_id", "unknown"),
            reason="deserialization_exception",
            details={"error": str(exc)},
        )
    return verify_envelope(env)


def verify_chain_link(
    current: ExecutionEnvelope,
    prev: Optional[ExecutionEnvelope],
) -> VerificationResult:
    try:
        schema = current.validate_schema()
    except Exception:
        return VerificationResult(
            valid=False,
            record_type="chain_link",
            record_id=getattr(current, "record_id", "unknown"),
            reason="schema_validation_exception",
        )

    if not _schema_contract_ok(schema):
        return VerificationResult(
            valid=False,
            record_type="chain_link",
            record_id=getattr(current, "record_id", "unknown"),
            reason="invalid_schema_return_contract",
        )

    if not schema.valid:
        return VerificationResult(
            valid=False,
            record_type="chain_link",
            record_id=current.record_id,
            reason="schema_validation_failed",
        )

    try:
        is_valid = current.verify_chain(prev)
    except Exception:
        return VerificationResult(
            valid=False,
            record_type="chain_link",
            record_id=current.record_id,
            reason="chain_verification_exception",
        )

    if not isinstance(is_valid, bool):
        return VerificationResult(
            valid=False,
            record_type="chain_link",
            record_id=current.record_id,
            reason="invalid_chain_return_contract",
        )

    if is_valid:
        return VerificationResult(
            valid=True,
            record_type="chain_link",
            record_id=current.record_id,
            reason="causal_hash_valid",
        )

    try:
        expected = ExecutionEnvelope.compute_causal_hash(prev)
        actual = current.causal_hash
        detail = {"expected": expected[:16] + "...", "actual": actual[:16] + "..."}
    except Exception:
        detail = {}

    return VerificationResult(
        valid=False,
        record_type="chain_link",
        record_id=current.record_id,
        reason="causal_hash_mismatch",
        details=detail,
    )


def verify_ledger_file(ledger_path: Path) -> dict:
    """Routes through ReplayEngine.stream_verify() — single source of truth."""
    from guardclaw.core.replay import ReplayEngine
    return ReplayEngine(mode="strict", silent=True).stream_verify(
        Path(ledger_path)
    ).to_dict()