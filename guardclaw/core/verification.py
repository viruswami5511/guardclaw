"""
guardclaw/core/verification.py

GEF Verification — v0.2.0

Protocol Law:
    verify_envelope(env: ExecutionEnvelope) is the ONLY signature verification path.
    All JSON-based entry points must call ExecutionEnvelope.from_dict() first,
    then pass the envelope to verify_envelope().

    Chain verification:  env.verify_chain(prev_env)
    Signature:           env.verify_signature()
    Both delegate to ExecutionEnvelope — zero local re-derivation.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guardclaw.core.models import ExecutionEnvelope, GENESIS_HASH


# ─────────────────────────────────────────────────────────────
# Result Type
# ─────────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    valid:       bool
    record_type: str
    record_id:   str
    reason:      str = ""
    details:     Dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}
        self.verified_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S."
        ) + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"

    def __repr__(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return f"VerificationResult({status}, {self.record_type}, {self.record_id})"

    def to_dict(self) -> dict:
        return {
            "valid":       self.valid,
            "record_type": self.record_type,
            "record_id":   self.record_id,
            "reason":      self.reason,
            "details":     self.details,
            "verified_at": self.verified_at,
        }


class VerificationError(Exception):
    pass


# ─────────────────────────────────────────────────────────────
# Primary Verification Entrypoint
# ─────────────────────────────────────────────────────────────

def verify_envelope(
    env: ExecutionEnvelope,
) -> VerificationResult:
    """
    Verify the Ed25519 signature of a single ExecutionEnvelope.

    Delegates entirely to env.verify_signature() which uses:
        env.canonical_bytes_for_signing()  (JCS over to_signing_dict())
        env.signer_public_key              (hex Ed25519 public key)

    No custom field reconstruction. No alternate signing path.
    """
    try:
        if not env.signature:
            return VerificationResult(
                valid=       False,
                record_type= env.record_type,
                record_id=   env.record_id,
                reason=      "Missing signature field",
            )

        is_valid = env.verify_signature()

        if is_valid:
            return VerificationResult(
                valid=       True,
                record_type= env.record_type,
                record_id=   env.record_id,
                reason=      "Signature verified",
                details={
                    "record_type":       env.record_type,
                    "sequence":          env.sequence,
                    "agent_id":          env.agent_id,
                    "signer_public_key": env.signer_public_key,
                    "timestamp":         env.timestamp,
                },
            )
        else:
            return VerificationResult(
                valid=       False,
                record_type= env.record_type,
                record_id=   env.record_id,
                reason=      "Signature mismatch",
                details={
                    "agent_id":          env.agent_id,
                    "signer_public_key": env.signer_public_key,
                },
            )

    except Exception as e:
        return VerificationResult(
            valid=       False,
            record_type= getattr(env, "record_type", "unknown"),
            record_id=   getattr(env, "record_id",   "unknown"),
            reason=      f"Verification error: {e}",
        )


def verify_envelope_from_dict(data: Dict[str, Any]) -> VerificationResult:
    """
    JSON-based entry point. Deserializes to ExecutionEnvelope first,
    then calls verify_envelope().
    """
    try:
        env = ExecutionEnvelope.from_dict(data)
        return verify_envelope(env)
    except Exception as e:
        return VerificationResult(
            valid=       False,
            record_type= data.get("record_type", "unknown"),
            record_id=   data.get("record_id",   "unknown"),
            reason=      f"Deserialization error: {e}",
        )


# ─────────────────────────────────────────────────────────────
# Chain Verification
# ─────────────────────────────────────────────────────────────

def verify_chain_link(
    current: ExecutionEnvelope,
    prev:    Optional[ExecutionEnvelope],
) -> VerificationResult:
    """
    Verify that current.causal_hash is correct given prev.
    Delegates to current.verify_chain(prev).
    """
    is_valid = current.verify_chain(prev)

    if is_valid:
        return VerificationResult(
            valid=       True,
            record_type= "chain_link",
            record_id=   current.record_id,
            reason=      "causal_hash valid",
            details=     {"sequence": current.sequence},
        )
    else:
        expected = current.expected_causal_hash_from(prev)
        return VerificationResult(
            valid=       False,
            record_type= "chain_link",
            record_id=   current.record_id,
            reason=      "causal_hash mismatch — chain broken",
            details={
                "sequence": current.sequence,
                "expected": expected[:16] + "...",
                "actual":   current.causal_hash[:16] + "...",
            },
        )


# ─────────────────────────────────────────────────────────────
# Ledger Batch Verification
# ─────────────────────────────────────────────────────────────

def verify_ledger_file(
    ledger_path: Path,
) -> Tuple[bool, List[VerificationResult]]:
    """
    Verify all envelopes in a GEF ledger JSONL file.

    Returns:
        (all_valid: bool, results: List[VerificationResult])
    """
    import json
    results: List[VerificationResult] = []
    envelopes: List[ExecutionEnvelope] = []

    with open(ledger_path, "r", encoding="utf-8") as f:
        for line_num, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
                env  = ExecutionEnvelope.from_dict(data)
                envelopes.append(env)
            except Exception as e:
                results.append(VerificationResult(
                    valid=       False,
                    record_type= "parse_error",
                    record_id=   f"line_{line_num}",
                    reason=      f"Parse error: {e}",
                ))

    for i, env in enumerate(envelopes):
        prev = envelopes[i - 1] if i > 0 else None
        results.append(verify_envelope(env))
        results.append(verify_chain_link(env, prev))

    all_valid = all(r.valid for r in results)
    return all_valid, results
