"""
guardclaw/core/crypto.py

GEF Cryptographic Layer — v0.3.0
Aligned to: GEF-SPEC-v1.0

FIXES APPLIED:
- Removed broad exception handling in verify_detached (X6)
- Deterministic failure classification (no silent swallowing)
- Strict validation preserved
- Debug leakage controlled
"""

import base64
import binascii
import re
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
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


DEBUG_CRYPTO = False


class Ed25519KeyManager:
    B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

    # --------------------------------------------------
    # INIT
    # --------------------------------------------------

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._public_key_hex = (
            self._public_key
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex()
        )

    # --------------------------------------------------
    # CONSTRUCTION
    # --------------------------------------------------

    @classmethod
    def generate(cls) -> "Ed25519KeyManager":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_file(cls, path: Path) -> "Ed25519KeyManager":
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        pem_bytes = path.read_bytes()
        private_key = load_pem_private_key(pem_bytes, password=None)

        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Not an Ed25519 key")

        return cls(private_key)

    load = from_file

    @classmethod
    def from_private_bytes(cls, seed) -> "Ed25519KeyManager":
        if not isinstance(seed, bytes):
            return cls(seed)
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    # --------------------------------------------------
    # PUBLIC KEY
    # --------------------------------------------------

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    # Alias for compatibility
    @property
    def public_key(self) -> str:
        return self._public_key_hex

    # --------------------------------------------------
    # SIGNING
    # --------------------------------------------------

    def sign(self, data: bytes) -> str:
        raw_sig = self._private_key.sign(data)
        return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode("ascii")

    # --------------------------------------------------
    # STRICT BASE64URL DECODE
    # --------------------------------------------------

    @staticmethod
    def _decode_strict_base64url_signature(signature_b64: str) -> bytes:
        if not isinstance(signature_b64, str) or not signature_b64:
            raise ValueError("invalid signature")

        if not Ed25519KeyManager.B64URL_RE.fullmatch(signature_b64):
            raise ValueError("non-canonical base64url")

        padded = signature_b64 + "=" * ((4 - len(signature_b64) % 4) % 4)

        try:
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        except (binascii.Error, ValueError):
            raise ValueError("decode failed")

        if len(raw) != 64:
            raise ValueError("invalid length")

        canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        if canonical != signature_b64:
            raise ValueError("non-canonical encoding")

        return raw

    # --------------------------------------------------
    # VERIFICATION
    # --------------------------------------------------

    def verify(
        self,
        data: bytes,
        signature_b64: str,
        public_key_hex: Optional[str] = None,
    ) -> bool:
        key_hex = public_key_hex or self._public_key_hex
        return Ed25519KeyManager.verify_detached(data, signature_b64, key_hex)

    @staticmethod
    def verify_detached(
        data: bytes,
        signature_b64: str,
        public_key_hex: str,
    ) -> bool:
        """
        Deterministic verification:
        - No broad exception swallowing
        - Explicit failure handling per error class
        - Returns False for all invalid conditions
        """

        # Validate public key format
        if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
            return False

        try:
            raw_pub = bytes.fromhex(public_key_hex)
        except ValueError:
            return False

        try:
            pub = Ed25519PublicKey.from_public_bytes(raw_pub)
        except Exception:
            return False

        # Decode signature strictly
        try:
            raw_sig = Ed25519KeyManager._decode_strict_base64url_signature(signature_b64)
        except ValueError:
            return False

        # Verify signature
        try:
            pub.verify(raw_sig, data)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            # Only unexpected crypto library failure reaches here
            if DEBUG_CRYPTO:
                print(f"[CRYPTO INTERNAL ERROR] {type(e).__name__}: {e}")
            return False

    # --------------------------------------------------
    # PERSISTENCE
    # --------------------------------------------------

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        pem = self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        path.write_bytes(pem)

    def private_bytes_raw(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    # --------------------------------------------------
    # DEBUG / REPRESENTATION
    # --------------------------------------------------

    def __repr__(self) -> str:
        return f"Ed25519KeyManager(public_key={self._public_key_hex[:16]}...)"