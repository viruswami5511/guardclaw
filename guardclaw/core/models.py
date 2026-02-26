"""
guardclaw/core/models.py

GEF Data Model — v0.2.0
Aligned to: GEF-SPEC-v1.0

THIS FILE IS LOCKED AFTER THIS VERSION.
Any change to contracts below requires a GEF spec version bump.

═══════════════════════════════════════════════════════════════════
PROTOCOL CONTRACTS — Locked. Changes require spec version bump.
═══════════════════════════════════════════════════════════════════

CONTRACT 1 — Signing
    bytes_signed = canonical_json_encode(env.to_signing_dict())
    algorithm    = Ed25519
    encoding     = base64url, no padding

CONTRACT 2 — Chain
    causal_hash  = SHA-256(canonical_json_encode(prev.to_chain_dict()))
    first_entry  = GENESIS_HASH ("0" * 64)
    payload      IN chain dict  → payload mutation breaks forward chain
    gef_version  IN chain dict  → version is part of chain identity

CONTRACT 3 — Timestamp
    format = YYYY-MM-DDTHH:MM:SS.mmmZ  (exactly 3 fractional digits, UTC, Z suffix)
    source = gef_timestamp() in guardclaw/core/time.py — nowhere else

CONTRACT 4 — Nonce
    format   = exactly 32 hex characters (128-bit random entropy)
    purpose  = anti-replay uniqueness guard per entry
    semantic = NOT monotonic. sequence = ordering. nonce = uniqueness.

CONTRACT 5 — Vocabulary
    record_type must be a RecordType constant.
    enforced at create() → ValueError
    validated at from_dict() time via validate_schema()

CONTRACT 6 — Version
    gef_version travels inside every envelope.
    included in to_signing_dict() and to_chain_dict().
    all envelopes in a single ledger MUST share identical gef_version.
    enforcement: replay raises GEFVersionError on version mismatch within ledger.

CONTRACT 7 — signer_public_key
    must be exactly 64 valid lowercase hex characters (32-byte Ed25519 public key raw)
    validated in validate_schema()

═══════════════════════════════════════════════════════════════════
CROSS-LANGUAGE GUARANTEE
═══════════════════════════════════════════════════════════════════
A Rust/Go/TypeScript implementation that reproduces:
    to_signing_dict()       — fields, names, includes gef_version + payload
    to_chain_dict()         — fields, names, includes gef_version + payload
    canonical_json_encode() — RFC 8785 JCS
    sha256(canonical_json_encode(prev.to_chain_dict()))

...will produce byte-for-byte identical chain hashes and signatures.
That is the definition of a working protocol.
═══════════════════════════════════════════════════════════════════
"""

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.time import gef_timestamp


# ─────────────────────────────────────────────────────────────
# GEF Constants
# ─────────────────────────────────────────────────────────────

GEF_VERSION  = "1.0"
GENESIS_HASH = "0" * 64

# Nonce: exactly 32 hex characters = 16 bytes = 128-bit entropy
_NONCE_HEX_LENGTH      = 32

# signer_public_key: raw Ed25519 public key = 32 bytes = 64 hex chars
_PUBLIC_KEY_HEX_LENGTH = 64

# Timestamp: strict GEF wire format
# YYYY-MM-DDTHH:MM:SS.mmmZ — exactly 3 fractional digits, Z suffix, no +00:00
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


# ─────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────

class GEFVersionError(Exception):
    """
    Raised when envelopes within a single ledger carry different gef_version values.
    A ledger must be version-homogeneous.
    """
    pass


# ─────────────────────────────────────────────────────────────
# Record Type Vocabulary — Locked and Enforced
# ─────────────────────────────────────────────────────────────

class RecordType:
    """
    GEF record_type string constants.

    These are the ONLY valid values for ExecutionEnvelope.record_type.

    Enforcement points:
        create()          → ValueError on unknown type
        validate_schema() → SchemaValidationResult with error on unknown type
        from_dict()       → trusts persisted data (caller must validate_schema)
    """
    GENESIS            = "genesis"
    AGENT_REGISTRATION = "agent_registration"
    INTENT             = "intent"
    EXECUTION          = "execution"
    RESULT             = "result"
    FAILURE            = "failure"
    DELEGATION         = "delegation"
    HEARTBEAT          = "heartbeat"
    TOOL_CALL          = "tool_call"
    TOMBSTONE          = "tombstone"
    ADMIN_ACTION       = "admin_action"


# Built once at import time. O(1) membership test.
_VALID_RECORD_TYPES: Set[str] = {
    RecordType.GENESIS,
    RecordType.AGENT_REGISTRATION,
    RecordType.INTENT,
    RecordType.EXECUTION,
    RecordType.RESULT,
    RecordType.FAILURE,
    RecordType.DELEGATION,
    RecordType.HEARTBEAT,
    RecordType.TOOL_CALL,
    RecordType.TOMBSTONE,
    RecordType.ADMIN_ACTION,
}


# ─────────────────────────────────────────────────────────────
# SchemaValidationResult
# ─────────────────────────────────────────────────────────────

@dataclass
class SchemaValidationResult:
    """
    Result of ExecutionEnvelope.validate_schema().

    Returned — not raised — so callers can choose hard fail vs log.
    bool(result) is True iff valid.
    """
    valid:  bool
    errors: List[str]

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        if self.valid:
            return "SchemaValidationResult(VALID)"
        return f"SchemaValidationResult(INVALID, errors={self.errors})"


# ─────────────────────────────────────────────────────────────
# ExecutionEnvelope — THE ONLY GEF LEDGER ENTRY TYPE
# ─────────────────────────────────────────────────────────────

@dataclass
class ExecutionEnvelope:
    """
    The singular GEF ledger entry. No other ledger type exists.

    See module docstring for all seven protocol contracts.
    """

    gef_version:       str
    record_id:         str
    record_type:       str
    agent_id:          str
    signer_public_key: str
    sequence:          int
    nonce:             str
    timestamp:         str
    causal_hash:       str
    payload:           Dict[str, Any]
    signature:         Optional[str] = None

    # ── Constructor ───────────────────────────────────────────

    @classmethod
    def create(
        cls,
        record_type:       str,
        agent_id:          str,
        signer_public_key: str,
        sequence:          int,
        payload:           Dict[str, Any],
        prev:              Optional["ExecutionEnvelope"] = None,
    ) -> "ExecutionEnvelope":
        """
        Create an unsigned ExecutionEnvelope with correct causal_hash.

        Hard enforces:
            record_type       — must be in _VALID_RECORD_TYPES
            payload           — must be a dict
            sequence          — must be non-negative int
            signer_public_key — must be 64-char hex string

        Call .sign(key_manager) immediately after:
            env = ExecutionEnvelope.create(...).sign(key_manager)
        """
        # ── Input enforcement ─────────────────────────────────
        if record_type not in _VALID_RECORD_TYPES:
            raise ValueError(
                f"Invalid record_type '{record_type}'. "
                f"Valid: {sorted(_VALID_RECORD_TYPES)}"
            )
        if not isinstance(payload, dict):
            raise TypeError(
                f"payload must be dict, got {type(payload).__name__}"
            )
        if not isinstance(sequence, int) or sequence < 0:
            raise ValueError(
                f"sequence must be non-negative int, got {sequence!r}"
            )
        if (
            not isinstance(signer_public_key, str)
            or len(signer_public_key) != _PUBLIC_KEY_HEX_LENGTH
        ):
            raise ValueError(
                f"signer_public_key must be {_PUBLIC_KEY_HEX_LENGTH}-char hex string, "
                f"got length {len(signer_public_key) if isinstance(signer_public_key, str) else type(signer_public_key).__name__}"
            )
        try:
            bytes.fromhex(signer_public_key)
        except ValueError:
            raise ValueError(
                f"signer_public_key is not valid hex: {signer_public_key!r}"
            )
        # ──────────────────────────────────────────────────────

        return cls(
            gef_version=       GEF_VERSION,
            record_id=         f"gef-{uuid.uuid4()}",
            record_type=       record_type,
            agent_id=          agent_id,
            signer_public_key= signer_public_key,
            sequence=          sequence,
            nonce=             secrets.token_hex(_NONCE_HEX_LENGTH // 2),
            timestamp=         gef_timestamp(),
            causal_hash=       cls._compute_causal_hash(prev),
            payload=           payload,
            signature=         None,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionEnvelope":
        """
        Deserialize from a JSONL line dict.
        THE ONLY deserialization path. Used by replay, CLI, verification.

        Trusts persisted data — does NOT enforce record_type or field formats.
        Callers MUST call validate_schema() to check stored data integrity.

        This separation lets replay distinguish:
            "unknown record_type injected post-write" (schema violation)
            vs "field missing entirely" (KeyError from from_dict)
        """
        return cls(
            gef_version=       data["gef_version"],
            record_id=         data["record_id"],
            record_type=       data["record_type"],
            agent_id=          data["agent_id"],
            signer_public_key= data["signer_public_key"],
            sequence=          data["sequence"],
            nonce=             data["nonce"],
            timestamp=         data["timestamp"],
            causal_hash=       data["causal_hash"],
            payload=           data.get("payload", {}),
            signature=         data.get("signature"),
        )

    # ── Schema Validation ─────────────────────────────────────

    def validate_schema(self) -> SchemaValidationResult:
        """
        Validate this envelope's schema against all GEF protocol rules.

        Called by:
            ReplayEngine.load()      → fail fast on corrupt/injected entry
            verify_envelope()        → before signature check
            CLI verify command       → before any processing

        Returns SchemaValidationResult — not bool — so callers
        can report the EXACT violation rather than silently pass/fail.
        """
        errors: List[str] = []

        # gef_version
        if self.gef_version != GEF_VERSION:
            errors.append(
                f"gef_version: expected '{GEF_VERSION}', got '{self.gef_version}'"
            )

        # record_type
        if self.record_type not in _VALID_RECORD_TYPES:
            errors.append(
                f"record_type '{self.record_type}' not in valid set: "
                f"{sorted(_VALID_RECORD_TYPES)}"
            )

        # record_id
        if not isinstance(self.record_id, str) or not self.record_id.startswith("gef-"):
            errors.append(
                f"record_id must be a string starting with 'gef-', got {self.record_id!r}"
            )

        # agent_id
        if not isinstance(self.agent_id, str) or not self.agent_id:
            errors.append("agent_id must be a non-empty string")

        # signer_public_key — CONTRACT 7
        if not isinstance(self.signer_public_key, str):
            errors.append(
                f"signer_public_key must be str, got {type(self.signer_public_key).__name__}"
            )
        elif len(self.signer_public_key) != _PUBLIC_KEY_HEX_LENGTH:
            errors.append(
                f"signer_public_key must be exactly {_PUBLIC_KEY_HEX_LENGTH} hex chars "
                f"(32-byte Ed25519 key), got {len(self.signer_public_key)}"
            )
        else:
            try:
                bytes.fromhex(self.signer_public_key)
            except ValueError:
                errors.append(
                    f"signer_public_key is not valid hex: {self.signer_public_key!r}"
                )

        # sequence
        if not isinstance(self.sequence, int) or self.sequence < 0:
            errors.append(
                f"sequence must be non-negative int, got {self.sequence!r}"
            )

        # nonce — CONTRACT 4
        if not isinstance(self.nonce, str):
            errors.append(f"nonce must be str, got {type(self.nonce).__name__}")
        elif len(self.nonce) != _NONCE_HEX_LENGTH:
            errors.append(
                f"nonce must be exactly {_NONCE_HEX_LENGTH} hex chars, "
                f"got {len(self.nonce)}"
            )
        else:
            try:
                bytes.fromhex(self.nonce)
            except ValueError:
                errors.append(f"nonce is not valid hex: {self.nonce!r}")

        # timestamp — CONTRACT 3: strict format YYYY-MM-DDTHH:MM:SS.mmmZ
        if not isinstance(self.timestamp, str):
            errors.append(
                f"timestamp must be str, got {type(self.timestamp).__name__}"
            )
        elif not _TIMESTAMP_RE.match(self.timestamp):
            errors.append(
                f"timestamp '{self.timestamp}' does not match GEF wire format "
                f"YYYY-MM-DDTHH:MM:SS.mmmZ (exactly 3 fractional digits, Z suffix)"
            )

        # causal_hash — must be 64 hex chars
        if not isinstance(self.causal_hash, str):
            errors.append(
                f"causal_hash must be str, got {type(self.causal_hash).__name__}"
            )
        elif len(self.causal_hash) != 64:
            errors.append(
                f"causal_hash must be 64 hex chars, got {len(self.causal_hash)}"
            )
        else:
            try:
                bytes.fromhex(self.causal_hash)
            except ValueError:
                errors.append(
                    f"causal_hash is not valid hex: {self.causal_hash!r}"
                )

        # payload
        if not isinstance(self.payload, dict):
            errors.append(
                f"payload must be dict, got {type(self.payload).__name__}"
            )

        return SchemaValidationResult(valid=len(errors) == 0, errors=errors)

    # ── The Three Canonical Contracts ─────────────────────────

    def to_signing_dict(self) -> Dict[str, Any]:
        """
        CONTRACT 1 — The EXACT dict signed by Ed25519.

        Includes: all fields EXCEPT signature.
        Includes: payload     (content must be signed)
        Includes: gef_version (envelope is self-describing)

        Cross-language: any implementation reproducing these exact field
        names and values and passing through JCS will verify a GEF signature.
        """
        return {
            "agent_id":          self.agent_id,
            "causal_hash":       self.causal_hash,
            "gef_version":       self.gef_version,
            "nonce":             self.nonce,
            "payload":           self.payload,
            "record_id":         self.record_id,
            "record_type":       self.record_type,
            "sequence":          self.sequence,
            "signer_public_key": self.signer_public_key,
            "timestamp":         self.timestamp,
        }

    def to_chain_dict(self) -> Dict[str, Any]:
        """
        CONTRACT 2 — The EXACT dict hashed to compute the NEXT entry's causal_hash.

        Includes: payload     (payload mutation must break forward chain)
        Includes: gef_version (version is part of chain identity)
        Excludes: signature   (signature is a function of this dict, not part of it)

        Invariant:
            next.causal_hash == SHA-256(JCS(prev.to_chain_dict()))

        NOTE: to_chain_dict() == to_signing_dict() by design.
        They are separate methods for semantic clarity:
            to_signing_dict() communicates "what is signed"
            to_chain_dict()   communicates "what is chained"
        This makes both contracts independently readable and testable.
        """
        return {
            "agent_id":          self.agent_id,
            "causal_hash":       self.causal_hash,
            "gef_version":       self.gef_version,
            "nonce":             self.nonce,
            "payload":           self.payload,
            "record_id":         self.record_id,
            "record_type":       self.record_type,
            "sequence":          self.sequence,
            "signer_public_key": self.signer_public_key,
            "timestamp":         self.timestamp,
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Full serialization including signature. Used for JSONL persistence ONLY.
        Not used for signing. Not used for chain hashing.
        """
        d = self.to_signing_dict().copy()
        d["signature"] = self.signature
        return d

    # ── Canonical Bytes ───────────────────────────────────────

    def canonical_bytes_for_signing(self) -> bytes:
        """
        THE ONLY path to produce bytes for signing or verification.

        canonical_json_encode(self.to_signing_dict())

        This is the complete specification of "what GuardClaw signs."
        No other path exists. No alternate method. No shortcut.
        """
        return canonical_json_encode(self.to_signing_dict())

    # ── Chain Hash ────────────────────────────────────────────

    @staticmethod
    def _compute_causal_hash(
        prev: Optional["ExecutionEnvelope"],
    ) -> str:
        """
        THE ONLY place SHA-256 is computed over chain data in this codebase.

        Rule (locked — CONTRACT 2):
            causal_hash = SHA-256(canonical_json_encode(prev.to_chain_dict()))

        Called only by create(). All chain verification goes through
        expected_causal_hash_from() which calls this.
        """
        if prev is None:
            return GENESIS_HASH
        return hashlib.sha256(
            canonical_json_encode(prev.to_chain_dict())
        ).hexdigest()

    def expected_causal_hash_from(
        self, prev: Optional["ExecutionEnvelope"]
    ) -> str:
        """
        What this entry's causal_hash SHOULD be given its predecessor.
        Used by replay and verification — not by the emitter.
        """
        return ExecutionEnvelope._compute_causal_hash(prev)

    # ── Signing ───────────────────────────────────────────────

    def sign(self, key_manager) -> "ExecutionEnvelope":
        """
        Sign this envelope in-place. Returns self for chaining.

        Computes canonical_bytes_for_signing() and calls key_manager.sign().
        Stores base64url (no-padding) Ed25519 signature in self.signature.

        Pattern:
            env = ExecutionEnvelope.create(...).sign(key_manager)

        Never call on an already-signed envelope — previous signature
        will be silently overwritten.
        """
        self.signature = key_manager.sign(self.canonical_bytes_for_signing())
        return self

    # ── Verification ──────────────────────────────────────────

    def verify_signature(
        self,
        override_public_key_hex: Optional[str] = None,
    ) -> bool:
        """
        Verify the Ed25519 signature over canonical_bytes_for_signing().

        Uses Ed25519KeyManager.verify_detached() — a @staticmethod that
        requires only a public key hex string. No key manager instance needed.
        This is the ONLY correct way to verify from an envelope, because
        the envelope stores only signer_public_key (hex), not a key manager.

        Args:
            override_public_key_hex: Verify against a different public key.
                                     Used by tests to confirm wrong keys fail.
                                     Defaults to self.signer_public_key.

        Returns:
            True  — signature valid over current canonical bytes
            False — unsigned, tampered field, wrong key, or any failure
            Never raises.

        GEF Law: returns False for ANY envelope where any signed field
            was mutated after sign() was called.
        """
        if not self.signature:
            return False

        from guardclaw.core.crypto import Ed25519KeyManager

        pubkey_hex = override_public_key_hex or self.signer_public_key
        data       = self.canonical_bytes_for_signing()

        return Ed25519KeyManager.verify_detached(data, self.signature, pubkey_hex)

    def verify_chain(
        self, prev: Optional["ExecutionEnvelope"]
    ) -> bool:
        """
        Verify this entry's causal_hash is correct given its predecessor.
        Delegates entirely to expected_causal_hash_from() — no local hash logic.
        Returns False if causal_hash doesn't match what it should be.
        """
        return self.causal_hash == self.expected_causal_hash_from(prev)

    def verify_sequence(self, expected: int) -> bool:
        """Return True if self.sequence == expected."""
        return self.sequence == expected

    def is_signed(self) -> bool:
        """Return True if this envelope carries a non-empty signature."""
        return bool(self.signature)
