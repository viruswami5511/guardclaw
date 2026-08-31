"""
guardclaw/core/encryption.py
AES-256-GCM payload encryption for GEF ledgers — Phase 3

Design:
    - Per-record key via HKDF(master, salt=session_id, info=record_id_keyid)
    - Random 96-bit IV (os.urandom(12)) per record
    - AAD = derived from canonical signing surface minus encryption-mutated fields
    - cipher_suite=1 signals encryption; absence = plaintext
    - Encrypt BEFORE sign (enforced by call order in ledger.py)
    - Base64url strict: no padding, no invalid chars

Hard rules:
    - Master key NEVER stored in ledger
    - Master key NEVER exposed in repr, str, or logs
    - No decryption inside ReplayEngine
    - cipher_suite=0 NEVER written
    - AAD derived from signing surface — never manually constructed

FIXES APPLIED (Audit Phase 3):
    - E7:  auth_tag base64url + byte-length validated after envelope mutation
    - E11/X3: master_key_hex renamed to export_master_key_hex() with DANGEROUS semantics
    - E2:  AAD exclusion logic documented explicitly (auditor false positive — justified)
"""

from __future__ import annotations

import json
import os
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import TYPE_CHECKING, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from guardclaw.core.canonical import canonical_json_encode

if TYPE_CHECKING:
    from guardclaw.core.models import ExecutionEnvelope

_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')
_GCM_TAG_LEN = 16
_KEY_LEN = 32
_IV_LEN = 12


# ── Base64url helpers ─────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, field: str = "value") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if '=' in value:
        raise ValueError(f"{field} must not contain '=' padding")
    if not _B64URL_RE.match(value):
        raise ValueError(f"{field} contains invalid base64url characters")
    padding = (4 - len(value) % 4) % 4
    return urlsafe_b64decode(value + "=" * padding)


def validate_b64url(value: str, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if '=' in value:
        raise ValueError(f"{field} must not contain '=' padding")
    if not _B64URL_RE.match(value):
        raise ValueError(f"{field} contains invalid base64url characters")


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(
    master_key: bytes,
    session_id: str,
    record_id: str,
    key_id: Optional[str],
) -> bytes:
    info = f"{record_id}_{key_id or ''}".encode("utf-8")
    hkdf = HKDF(
        algorithm=SHA256(),
        length=_KEY_LEN,
        salt=session_id.encode("utf-8"),
        info=info,
    )
    return hkdf.derive(master_key)


# ── AAD construction ──────────────────────────────────────────────────────────

def _build_aad(env: "ExecutionEnvelope") -> bytes:
    """
    AAD = canonical signing surface minus fields mutated by encryption.

    Derived from signing surface — never manually constructed.
    This guarantees: any field added to the envelope in future phases
    is automatically included in AAD without any manual update here.

    Force-copies the dict so the original signing surface is never mutated.

    Excluded fields and justification (Audit E2 — justified exclusion):
        payload      — replaced with ciphertext during encrypt(); value changes
        iv           — generated during encrypt(); does not exist yet at AAD time
        auth_tag     — produced by AES-GCM during encrypt(); does not exist yet
        cipher_suite — set during encrypt(); does not exist yet at AAD time
        signature    — already absent from canonical_signing_surface()

    These four fields are excluded because they are produced BY the encryption
    operation itself — they cannot be part of the input to that same operation.
    All other envelope fields (agent_id, session_id, record_id, causal_hash,
    sequence, timestamp, nonce, signer_public_key, etc.) ARE bound in AAD,
    making AAD a full authenticated binding of envelope identity.

    Audit verdict: E2 is a FALSE POSITIVE. The exclusion is protocol-correct.
    """
    surface = dict(env.canonical_signing_surface())  # force copy — never mutate original
    for k in ("payload", "iv", "auth_tag", "cipher_suite"):
        surface.pop(k, None)
    return canonical_json_encode(surface)


# ── EncryptionManager ─────────────────────────────────────────────────────────

class EncryptionManager:
    """
    Manages AES-256-GCM encryption/decryption for GEF envelopes.
    Master key held in memory only — never written to ledger.
    Master key never exposed in repr, str, or any serialization path.
    """

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != _KEY_LEN:
            raise ValueError(
                f"master_key must be {_KEY_LEN} bytes, got {len(master_key)}"
            )
        self._master_key = master_key

    @classmethod
    def generate(cls) -> "EncryptionManager":
        return cls(os.urandom(_KEY_LEN))

    @classmethod
    def from_hex(cls, hex_key: str) -> "EncryptionManager":
        try:
            key = bytes.fromhex(hex_key)
        except ValueError as e:
            raise ValueError(f"Invalid hex key: {e}") from e
        return cls(key)

    # FIX E11/X3 — renamed from master_key_hex to export_master_key_hex()
    # Old name `master_key_hex` was a casual property implying read-only access.
    # New name `export_master_key_hex()` signals intentional, dangerous export.
    # Callers must treat the return value as a root secret — see docstring.
    def export_master_key_hex(self) -> str:
        """
        ⚠️  DANGEROUS — Export master key as hex for secure out-of-band storage ONLY.

        This value is the root secret of the entire encryption system.
        Caller obligations (non-negotiable):
            - NEVER log this value
            - NEVER include in any API response
            - NEVER write to any ledger record
            - Store ONLY in a secrets manager (HSM, Vault, AWS Secrets Manager)
            - Treat with the same security level as an Ed25519 private key

        This method exists solely for initial key provisioning and backup.
        It must never appear in any hot path.
        """
        return self._master_key.hex()

    def __repr__(self) -> str:
        """Master key is never exposed in repr."""
        return "EncryptionManager(<REDACTED>)"

    def __str__(self) -> str:
        """Master key is never exposed in str."""
        return "EncryptionManager(<REDACTED>)"

    def encrypt(self, env: "ExecutionEnvelope") -> "ExecutionEnvelope":
        """
        Encrypt envelope payload in-place.

        Protocol order (non-negotiable):
            1. Validate plaintext state
            2. Build AAD from signing surface minus encryption-mutated fields
            3. Derive per-record key
            4. Generate random IV
            5. Encrypt plaintext with AAD
            6. Validate auth_tag byte length (internal invariant pre-encode)
            7. Set cipher_suite=1, iv, auth_tag, payload=ciphertext
            8. Validate serialized auth_tag base64url + decoded length (E7 fix)
            9. Return envelope (caller must call sign() after this)
        """
        if env.cipher_suite is not None:
            raise ValueError("envelope is already encrypted")
        if not isinstance(env.payload, dict):
            raise ValueError("plaintext payload must be a dict")

        # Step 2 — AAD derived from signing surface BEFORE any mutation
        aad = _build_aad(env)

        # Step 3 — per-record key
        record_key = _derive_key(
            self._master_key,
            env.session_id,
            env.record_id,
            env.key_id,
        )

        # Step 4 — random IV
        iv_bytes = os.urandom(_IV_LEN)

        # Step 5 — encrypt
        plaintext = canonical_json_encode(env.payload)
        aesgcm = AESGCM(record_key)
        ciphertext_with_tag = aesgcm.encrypt(iv_bytes, plaintext, aad)

        ciphertext = ciphertext_with_tag[:-_GCM_TAG_LEN]
        auth_tag_bytes = ciphertext_with_tag[-_GCM_TAG_LEN:]

        # Step 6 — internal byte-length invariant before encoding
        if len(auth_tag_bytes) != _GCM_TAG_LEN:
            raise ValueError(
                f"Protocol invariant violated: auth_tag must be exactly "
                f"{_GCM_TAG_LEN} bytes, got {len(auth_tag_bytes)}"
            )

        # Step 7 — mutate envelope fields
        env.payload = b64url_encode(ciphertext)
        env.iv = b64url_encode(iv_bytes)
        env.auth_tag = b64url_encode(auth_tag_bytes)
        env.cipher_suite = 1

        # FIX E7 — validate serialized auth_tag on the envelope AFTER mutation.
        # Step 6 validates the raw bytes before encoding; this step validates
        # the serialized base64url string on the envelope object itself,
        # catching any encoding corruption or accidental field re-assignment
        # that could occur between Step 6 and the caller's sign() invocation.
        validate_b64url(env.auth_tag, "auth_tag")
        decoded_tag = b64url_decode(env.auth_tag, "auth_tag")
        if len(decoded_tag) != _GCM_TAG_LEN:
            raise ValueError(
                f"Protocol invariant violated: serialized auth_tag decodes to "
                f"{len(decoded_tag)} bytes, expected {_GCM_TAG_LEN}"
            )

        return env

    def decrypt(self, env: "ExecutionEnvelope") -> dict:
        """
        Decrypt envelope payload. Returns original plaintext dict.

        Raises:
            ValueError   — envelope not encrypted or fields invalid
            InvalidTag   — ciphertext tampered or AAD mismatch
        """
        if env.cipher_suite != 1:
            raise ValueError("envelope is not encrypted (cipher_suite != 1)")
        if not isinstance(env.payload, str):
            raise ValueError("encrypted payload must be a base64url string")
        if env.iv is None or env.auth_tag is None:
            raise ValueError("encrypted envelope missing iv or auth_tag")

        validate_b64url(env.payload, "payload")
        validate_b64url(env.iv, "iv")
        validate_b64url(env.auth_tag, "auth_tag")

        ciphertext = b64url_decode(env.payload, "payload")
        iv_bytes = b64url_decode(env.iv, "iv")
        auth_tag = b64url_decode(env.auth_tag, "auth_tag")

        if len(iv_bytes) != _IV_LEN:
            raise ValueError(
                f"iv must be exactly {_IV_LEN} bytes, got {len(iv_bytes)}"
            )
        if len(auth_tag) != _GCM_TAG_LEN:
            raise ValueError(
                f"auth_tag must be exactly {_GCM_TAG_LEN} bytes, "
                f"got {len(auth_tag)}"
            )

        aad = _build_aad(env)

        record_key = _derive_key(
            self._master_key,
            env.session_id,
            env.record_id,
            env.key_id,
        )

        aesgcm = AESGCM(record_key)
        plaintext = aesgcm.decrypt(iv_bytes, ciphertext + auth_tag, aad)

        return json.loads(plaintext.decode("utf-8"))