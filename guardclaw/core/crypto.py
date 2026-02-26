"""
guardclaw/core/crypto.py

GEF Cryptographic Layer — v0.2.0
Aligned to: GEF-SPEC-v1.0

Key contracts:
    public_key_hex          : @property → 64-char lowercase hex  (NO parentheses)
    sign(data)              : bytes → base64url str, no padding
    verify_detached(...)    : @staticmethod — verifies with ONLY a pubkey hex string
                              This is the method models.py MUST call from verify_signature()
    verify(...)             : instance method — verifies against THIS key manager's key

CRITICAL:
    public_key_hex is a @property. Access as key.public_key_hex, NOT key.public_key_hex().
    models.py verify_signature() MUST call Ed25519KeyManager.verify_detached(), not verify().
    verify() requires a key manager instance. verify_detached() requires only a hex string.
"""

import base64
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class Ed25519KeyManager:
    """
    GEF Ed25519 key manager.

    Public surface:
        Ed25519KeyManager.generate()                        → new random key
        Ed25519KeyManager.from_file(path)                  → load PEM private key
        Ed25519KeyManager.from_private_bytes(seed)         → load from raw 32-byte seed
        Ed25519KeyManager.verify_detached(data, sig, hex)  → @staticmethod, no instance needed

        key.public_key_hex          (@property) → 64-char lowercase hex
        key.sign(data: bytes)                   → base64url str (no padding)
        key.verify(data, sig, hex)              → bool (instance method)
        key.save(path)                          → write PEM private key
        key.private_bytes_raw()                 → raw 32-byte seed
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key:    Ed25519PrivateKey = private_key
        self._public_key:     Ed25519PublicKey  = private_key.public_key()
        # Pre-compute and cache — never recomputed on each access
        self._public_key_hex: str = (
            self._public_key
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex()
        )

    # ── Construction ──────────────────────────────────────────

    @classmethod
    def generate(cls) -> "Ed25519KeyManager":
        """Generate a new random Ed25519 key pair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_file(cls, path: Path) -> "Ed25519KeyManager":
        """
        Load an Ed25519 private key from a PEM file.
        Raises FileNotFoundError if path does not exist.
        Raises ValueError if the file is not a valid Ed25519 PEM key.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        pem_bytes = path.read_bytes()
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            private_key = load_pem_private_key(pem_bytes, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError(
                    f"Key file {path} does not contain an Ed25519 private key"
                )
            return cls(private_key)
        except Exception as exc:
            raise ValueError(
                f"Failed to load Ed25519 key from {path}: {exc}"
            ) from exc

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> "Ed25519KeyManager":
        """
        Load an Ed25519 key from a raw 32-byte seed.
        Raises ValueError if seed is not exactly 32 bytes.
        """
        if len(seed) != 32:
            raise ValueError(
                f"Ed25519 seed must be 32 bytes, got {len(seed)}"
            )
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    # ── Public Key ────────────────────────────────────────────

    @property
    def public_key_hex(self) -> str:
        """
        64-character lowercase hex string of the Ed25519 public key (32 bytes).

        THIS IS A @property — access as key.public_key_hex (NO parentheses).

        GEF protocol guarantee:
            len(key.public_key_hex) == 64
            all(c in '0123456789abcdef' for c in key.public_key_hex)
        """
        return self._public_key_hex

    # ── Signing ───────────────────────────────────────────────

    def sign(self, data: bytes) -> str:
        """
        Sign data with Ed25519. Returns base64url string, no '=' padding.

        Args:
            data: Raw bytes to sign. Caller is responsible for canonicalization
                  (models.py calls canonical_bytes_for_signing() before this).

        Returns:
            base64url-encoded signature, no padding. Always 86 characters.
        """
        raw_sig = self._private_key.sign(data)
        return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode("ascii")

    # ── Verification — INSTANCE ───────────────────────────────

    def verify(
        self,
        data:           bytes,
        signature_b64:  str,
        public_key_hex: Optional[str] = None,
    ) -> bool:
        """
        Verify an Ed25519 signature using this key manager's public key
        (or an explicit override).

        Args:
            data:           Raw bytes that were signed.
            signature_b64:  base64url signature (with or without padding).
            public_key_hex: 64-char hex override. Defaults to own public key.

        Returns:
            True if valid. False for ANY failure. Never raises.

        NOTE: models.py MUST use verify_detached() instead of this method,
              because verify_signature() has no key manager instance — only
              the public key hex stored on the envelope.
        """
        key_hex = public_key_hex or self._public_key_hex
        return Ed25519KeyManager.verify_detached(data, signature_b64, key_hex)

    # ── Verification — STATIC ─────────────────────────────────

    @staticmethod
    def verify_detached(
        data:           bytes,
        signature_b64:  str,
        public_key_hex: str,
    ) -> bool:
        """
        Verify an Ed25519 signature using ONLY a public key hex string.

        No Ed25519KeyManager instance required. No private key required.
        This is the method ExecutionEnvelope.verify_signature() MUST call.

        Args:
            data:           Raw bytes that were signed (canonical bytes).
            signature_b64:  base64url signature string (with or without padding).
            public_key_hex: 64-char lowercase hex string of the signer's public key.

        Returns:
            True if the signature is valid over data with the given public key.
            False for ANY failure — wrong key, bad encoding, wrong length,
            corrupted signature. Never raises.

        GEF enforcement:
            - public_key_hex must be exactly 64 hex chars (32 bytes)
            - signature_b64 must decode to exactly 64 bytes
            - Verification uses Ed25519 raw (not prehashed)
        """
        try:
            if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
                return False

            raw_pub = bytes.fromhex(public_key_hex)
            pub     = Ed25519PublicKey.from_public_bytes(raw_pub)

            # Re-add base64url padding if stripped
            padding    = 4 - len(signature_b64) % 4
            padded_sig = signature_b64 + "=" * (padding % 4)
            raw_sig    = base64.urlsafe_b64decode(padded_sig)

            if len(raw_sig) != 64:
                return False

            pub.verify(raw_sig, data)
            return True

        except Exception:
            return False

    # ── Persistence ───────────────────────────────────────────

    def save(self, path: Path) -> None:
        """
        Write the private key to disk as a PEM file.
        Creates parent directories if needed.
        Raises RuntimeError on write failure.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            pem = self._private_key.private_bytes(
                encoding=             Encoding.PEM,
                format=               PrivateFormat.PKCS8,
                encryption_algorithm= NoEncryption(),
            )
            path.write_bytes(pem)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to save Ed25519 key to {path}: {exc}"
            ) from exc

    def private_bytes_raw(self) -> bytes:
        """
        Return the raw 32-byte private key seed.
        Use only for secure backup — never log or transmit.
        """
        return self._private_key.private_bytes(
            encoding=             Encoding.Raw,
            format=               PrivateFormat.Raw,
            encryption_algorithm= NoEncryption(),
        )

    def __repr__(self) -> str:
        return (
            f"Ed25519KeyManager(public_key_hex={self._public_key_hex[:16]}...)"
        )
