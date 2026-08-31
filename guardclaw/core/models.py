"""
guardclaw/core/models.py
GEF Envelope Model — v1.3.1

Protocol invariants enforced here:
    - validate_schema() raises SchemaValidationError — fail-closed, no advisory path
    - collect_schema_errors() for diagnostics and replay engine only
    - cipher_suite=0 rejected at to_dict() — never written
    - cipher_suite=1 requires iv + auth_tag + str payload — fully validated
    - signer_public_key validated as 64-char hex
    - causal_hash validated as 64-char hex
    - RecordType.normalize() enforces uppercase before validation
    - signature validated as base64url in schema (S4 fix)

FIXES APPLIED (Audit Phase 3):
    - S4: signature base64url format enforced in collect_schema_errors()
    - E10: cipher_suite invariant in from_dict() is correct — deserialization
           must accept disk data; cipher_suite=1 requires iv+auth_tag+str payload
           which is enforced by the schema layer above. Justified.
"""

from __future__ import annotations
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager

GEF_VERSION = "1.0"
GENESIS_HASH = "0" * 64

VALID_RECORD_TYPES = frozenset({
    "GENESIS", "EXECUTION", "RESULT", "FAILURE", "TOOL_CALL", "TOOL_RESULT",
    "DECISION", "INTENT", "OBSERVATION", "MEMORY_READ", "MEMORY_WRITE",
    "HANDOFF", "INTERRUPTED", "ERROR", "CUSTOM",
})

KNOWN_FIELDS = {
    "gef_version", "record_id", "record_type", "agent_id",
    "session_id", "sequence", "timestamp", "causal_hash",
    "nonce", "payload", "signer_public_key", "signature",
    "key_id", "trusted_timestamp",
    "cipher_suite", "iv", "auth_tag",
}

_VALID_CIPHER_SUITES = frozenset({1})  # None=plaintext, 1=AES-256-GCM
_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


class RecordType:
    GENESIS      = "GENESIS"
    EXECUTION    = "EXECUTION"
    RESULT       = "RESULT"
    FAILURE      = "FAILURE"
    TOOL_CALL    = "TOOL_CALL"
    TOOL_RESULT  = "TOOL_RESULT"
    DECISION     = "DECISION"
    INTENT       = "INTENT"
    OBSERVATION  = "OBSERVATION"
    MEMORY_READ  = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    HANDOFF      = "HANDOFF"
    INTERRUPTED  = "INTERRUPTED"
    ERROR        = "ERROR"
    CUSTOM       = "CUSTOM"

    @classmethod
    def normalize(cls, raw: str) -> str:
        if not isinstance(raw, str):
            raise ValueError("record_type must be str")
        upper = raw.upper()
        if upper in VALID_RECORD_TYPES:
            return upper
        raise ValueError(
            f"Invalid record_type {raw!r}. Valid: {sorted(VALID_RECORD_TYPES)}"
        )


@dataclass
class SchemaResult:
    valid: bool
    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid


SchemaValidationResult = SchemaResult


class GEFVersionError(Exception):
    """Raised when a ledger's gef_version is unsupported."""


class SchemaValidationError(Exception):
    """
    Raised by validate_schema() when any envelope invariant is violated.

    Protocol rule: invalid state must never silently proceed.
    Use collect_schema_errors() for diagnostic/non-raising checks.
    """


@dataclass
class ExecutionEnvelope:
    # ── 12 canonical v1.0 fields ──────────────────────────────────────────────
    gef_version:        str
    record_id:          str
    record_type:        str
    agent_id:           str
    session_id:         str
    sequence:           int
    timestamp:          str
    causal_hash:        str
    nonce:              str
    payload:            Union[Dict[str, Any], str]
    signer_public_key:  str
    signature:          Optional[str] = field(default=None)

    # ── Phase 1 optional fields ───────────────────────────────────────────────
    key_id:             Optional[str]            = field(default=None)
    trusted_timestamp:  Optional[Dict[str, Any]] = field(default=None)

    # ── Phase 3 encryption fields ─────────────────────────────────────────────
    cipher_suite:       Optional[int] = field(default=None)
    iv:                 Optional[str] = field(default=None)
    auth_tag:           Optional[str] = field(default=None)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        record_type:        str,
        agent_id:           str,
        session_id:         str,
        signer_public_key:  str,
        sequence:           int,
        payload:            Dict[str, Any],
        prev:               Optional["ExecutionEnvelope"],
        key_id:             Optional[str] = None,
        trusted_timestamp:  Optional[Dict[str, Any]] = None,
    ) -> "ExecutionEnvelope":
        causal_hash = _compute_causal_hash(prev) if prev else GENESIS_HASH
        return cls(
            gef_version       = GEF_VERSION,
            record_id         = f"gef-{uuid.uuid4()}",
            record_type       = RecordType.normalize(record_type),
            agent_id          = agent_id,
            session_id        = session_id,
            sequence          = sequence,
            timestamp         = _utc_now(),
            causal_hash       = causal_hash,
            nonce             = uuid.uuid4().hex,
            payload           = payload,
            signer_public_key = signer_public_key,
            signature         = None,
            key_id            = key_id,
            trusted_timestamp = trusted_timestamp,
            cipher_suite      = None,
            iv                = None,
            auth_tag          = None,
        )

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "gef_version":       self.gef_version,
            "record_id":         self.record_id,
            "record_type":       self.record_type,
            "agent_id":          self.agent_id,
            "session_id":        self.session_id,
            "sequence":          self.sequence,
            "timestamp":         self.timestamp,
            "causal_hash":       self.causal_hash,
            "nonce":             self.nonce,
            "payload":           self.payload,
            "signer_public_key": self.signer_public_key,
            "signature":         self.signature if self.signature is not None else "",
        }
        if self.key_id is not None:
            d["key_id"] = self.key_id
        if self.trusted_timestamp is not None:
            d["trusted_timestamp"] = self.trusted_timestamp
        if self.cipher_suite is not None:
            if self.cipher_suite == 0:
                raise ValueError(
                    "Protocol invariant violated: cipher_suite=0 must never "
                    "be written. Use None for plaintext."
                )
            d["cipher_suite"] = self.cipher_suite
        if self.iv is not None:
            d["iv"] = self.iv
        if self.auth_tag is not None:
            d["auth_tag"] = self.auth_tag
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExecutionEnvelope":
        # E10 — deserialization MUST accept cipher_suite from disk.
        # Invariant enforcement (iv+auth_tag+str payload required for cs=1)
        # is the responsibility of the schema layer (collect_schema_errors),
        # not from_dict. from_dict is a faithful deserializer, not a validator.
        raw_cs = d.get("cipher_suite")
        if raw_cs is not None and raw_cs not in _VALID_CIPHER_SUITES:
            raise ValueError(
                f"from_dict: unsupported cipher_suite={raw_cs!r}. "
                f"Valid: {sorted(_VALID_CIPHER_SUITES)} or absent."
            )
        return cls(
            gef_version       = d["gef_version"],
            record_id         = d["record_id"],
            record_type       = RecordType.normalize(d["record_type"]) if isinstance(d["record_type"], str) else d["record_type"],
            agent_id          = d["agent_id"],
            session_id        = d["session_id"],
            sequence          = int(d["sequence"]),
            timestamp         = d["timestamp"],
            causal_hash       = d["causal_hash"],
            nonce             = d["nonce"],
            payload           = d["payload"],
            signer_public_key = d["signer_public_key"],
            signature         = d.get("signature") or None,
            key_id            = d.get("key_id"),
            trusted_timestamp = d.get("trusted_timestamp"),
            cipher_suite      = raw_cs,
            iv                = d.get("iv"),
            auth_tag          = d.get("auth_tag"),
        )

    # ── Signing surface ───────────────────────────────────────────────────────

    def canonical_signing_surface(self) -> Dict[str, Any]:
        surface = self.to_dict()
        surface.pop("signature", None)
        for k in ("key_id", "trusted_timestamp"):
            if k in surface and surface[k] is None:
                raise ValueError(
                    f"Protocol invariant violated: '{k}' is None in signing surface."
                )
        return surface

    def to_signing_dict(self) -> Dict[str, Any]:
        return self.canonical_signing_surface()

    def canonical_bytes_for_signing(self) -> bytes:
        return canonical_json_encode(self.canonical_signing_surface())

    # ── Signature operations ──────────────────────────────────────────────────

    def sign(self, key_manager: Ed25519KeyManager) -> "ExecutionEnvelope":
        surface = canonical_json_encode(self.canonical_signing_surface())
        self.signature = key_manager.sign(surface)
        return self

    def verify_signature(
        self,
        override_public_key_hex: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Returns:
            (True,  None)       — valid
            (False, "missing")  — signature is None or empty
            (False, "encoding") — not valid base64url
            (False, "mismatch") — decodes but Ed25519 fails
            (False, "error")    — unexpected exception
        """
        pub_hex = override_public_key_hex or self.signer_public_key

        if self.signature is None:
            return False, "missing"
        if not isinstance(self.signature, str) or not self.signature.strip():
            return False, "encoding"
        try:
            Ed25519KeyManager._decode_strict_base64url_signature(self.signature)
        except Exception:
            return False, "encoding"

        try:
            surface = canonical_json_encode(self.canonical_signing_surface())
            ok = Ed25519KeyManager.verify_detached(
                data=surface,
                signature_b64=self.signature,
                public_key_hex=pub_hex,
            )
            return (True, None) if ok else (False, "mismatch")
        except Exception:
            return False, "error"

    # ── Chain verification ────────────────────────────────────────────────────

    @classmethod
    def compute_causal_hash(cls, prev: Optional["ExecutionEnvelope"]) -> str:
        return _compute_causal_hash(prev) if prev else GENESIS_HASH

    def verify_chain(self, prev: Optional["ExecutionEnvelope"]) -> bool:
        expected = self.compute_causal_hash(prev)
        return self.causal_hash == expected

    # ── Schema validation — fail-closed ──────────────────────────────────────

    def validate_schema(self) -> "SchemaResult":
        """
        Enforce all envelope invariants — fail-closed.

        Raises SchemaValidationError on any violation.
        Returns SchemaResult(valid=True) only when all invariants pass.
        """
        result = self.collect_schema_errors()
        if not result.valid:
            raise SchemaValidationError(
                f"Schema validation failed: {result.errors}"
            )
        return result

    def collect_schema_errors(self) -> "SchemaResult":
        """
        Non-raising schema check — returns full error list.

        Use in: replay engine, diagnostics, audits, tests.
        Never use in: emit(), sign(), encrypt() — those must be fail-closed.
        """
        errors: List[str] = []

        if not isinstance(self.gef_version, str) or self.gef_version != GEF_VERSION:
            errors.append("invalid_gef_version")
        if not isinstance(self.record_id, str) or not self.record_id.startswith("gef-"):
            errors.append(f"invalid_record_id:{self.record_id!r}")
        if self.record_type not in VALID_RECORD_TYPES:
            errors.append(f"invalid_record_type:{self.record_type!r}")
        if not isinstance(self.agent_id, str) or not self.agent_id:
            errors.append("invalid_agent_id")
        if not isinstance(self.session_id, str) or not self.session_id:
            errors.append("invalid_session_id")
        if not isinstance(self.sequence, int) or self.sequence < 0:
            errors.append(f"invalid_sequence:{self.sequence!r}")
        if not isinstance(self.timestamp, str) or not self.timestamp:
            errors.append("invalid_timestamp")
        ch = self.causal_hash
        if not isinstance(ch, str) or len(ch) != 64:
            errors.append("invalid_causal_hash_len")
        elif not _HEX_RE.match(ch):
            errors.append("invalid_causal_hash_not_hex")
        if not isinstance(self.nonce, str) or not self.nonce:
            errors.append("invalid_nonce")
        spk = self.signer_public_key
        if not isinstance(spk, str) or len(spk) != 64:
            errors.append("invalid_signer_public_key")
        elif not _HEX_RE.match(spk):
            errors.append("invalid_signer_public_key_not_hex")

        # FIX S4 — signature base64url format enforced as a model invariant.
        # Previously, signature format was only validated in verify_signature().
        # This meant a malformed signature string could pass schema validation,
        # enter the ledger, and fail unpredictably at verify time.
        # Invariant: if a signature is present it must be valid base64url.
        # None and "" are both valid (unsigned envelope — caught by verify_signature).
        if self.signature is not None and self.signature != "":
            if not isinstance(self.signature, str):
                errors.append("invalid_signature_type")
            else:
                _validate_b64url_field(self.signature, "signature", errors)

        if self.key_id is not None:
            if not isinstance(self.key_id, str) or not self.key_id:
                errors.append("invalid_key_id")
        if self.trusted_timestamp is not None:
            if not isinstance(self.trusted_timestamp, dict):
                errors.append("invalid_trusted_timestamp_type")
            else:
                tsr = self.trusted_timestamp.get("tsr_base64")
                if not isinstance(tsr, str) or not tsr:
                    errors.append("trusted_timestamp_tsr_base64_must_be_str")
                if "hash_alg" not in self.trusted_timestamp:
                    errors.append("trusted_timestamp_missing_hash_alg")
                for k, v in self.trusted_timestamp.items():
                    if isinstance(v, (dict, list)):
                        errors.append(
                            f"trusted_timestamp_must_be_flat:nested_value_at_{k}"
                        )

        # ── Phase 3 encryption invariants ─────────────────────────────────────
        if self.cipher_suite is None:
            if self.iv is not None:
                errors.append("plaintext_envelope_must_not_have_iv")
            if self.auth_tag is not None:
                errors.append("plaintext_envelope_must_not_have_auth_tag")
            if not isinstance(self.payload, dict):
                errors.append("plaintext_payload_must_be_dict")
        elif self.cipher_suite == 1:
            if not self.iv:
                errors.append("encrypted_envelope_missing_iv")
            if not self.auth_tag:
                errors.append("encrypted_envelope_missing_auth_tag")
            if not isinstance(self.payload, str) or not self.payload:
                errors.append("encrypted_payload_must_be_base64url_string")
            if self.iv:
                _validate_b64url_field(self.iv, "iv", errors)
            if self.auth_tag:
                _validate_b64url_field(self.auth_tag, "auth_tag", errors)
            if isinstance(self.payload, str) and self.payload:
                _validate_b64url_field(self.payload, "payload", errors)
        else:
            errors.append(f"invalid_cipher_suite:{self.cipher_suite!r}")

        return SchemaResult(valid=len(errors) == 0, errors=errors)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_b64url_field(value: str, field_name: str, errors: List[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{field_name}_must_be_string")
        return
    if '=' in value:
        errors.append(f"{field_name}_must_not_have_padding")
    if not _B64URL_RE.match(value):
        errors.append(f"{field_name}_invalid_base64url_chars")


def _compute_causal_hash(prev: "ExecutionEnvelope") -> str:
    d = prev.to_dict()
    d.pop("signature", None)
    return hashlib.sha256(canonical_json_encode(d)).hexdigest()


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def signing_surface(d: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(d)
    out.pop("signature", None)
    return out


def first_schema_error(errors: List[str]) -> str:
    return errors[0] if errors else "unknown_schema_error"


def check_unknown_fields(d: Dict[str, Any]) -> List[str]:
    return [k for k in d if k not in KNOWN_FIELDS]