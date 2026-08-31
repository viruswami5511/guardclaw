"""
guardclaw/core/kms.py

Pluggable Key Management & Hardware Security Isolation Layer.
Enables GuardClaw signing keys to reside outside the agent process/container,
such as in AWS KMS, Azure Key Vault, HashiCorp Vault, or an isolated enclave.
"""

from __future__ import annotations
import abc
from pathlib import Path
from typing import Optional, Union

from guardclaw.core.crypto import Ed25519KeyManager


class KeyProvider(abc.ABC):
    """
    Abstract interface for out-of-process and in-process key signing providers.
    """

    @property
    @abc.abstractmethod
    def public_key_hex(self) -> str:
        """Hex-encoded 64-character public key string."""
        ...

    @abc.abstractmethod
    def sign_bytes(self, canonical_bytes: bytes) -> str:
        """
        Sign canonical bytes and return a base64url-encoded detached signature without padding.
        """
        ...


class LocalKeyProvider(KeyProvider):
    """
    Standard local in-memory/file Ed25519 key provider.
    """

    def __init__(self, key_manager: Optional[Ed25519KeyManager] = None) -> None:
        self._key_manager = key_manager or Ed25519KeyManager.generate()

    @classmethod
    def from_file(cls, key_path: Union[str, Path]) -> "LocalKeyProvider":
        km = Ed25519KeyManager.load(Path(key_path))
        return cls(km)

    @property
    def key_manager(self) -> Ed25519KeyManager:
        return self._key_manager

    @property
    def public_key_hex(self) -> str:
        return self._key_manager.public_key_hex

    def sign_bytes(self, canonical_bytes: bytes) -> str:
        return self._key_manager.sign_detached(canonical_bytes)


class KMSKeyProvider(KeyProvider):
    """
    KMS / Hardware Isolation Provider interface for AWS KMS, Azure Key Vault,
    or HashiCorp Vault Transit Engine.
    """

    def __init__(
        self,
        key_arn_or_id: str,
        provider_type: str = "aws-kms",
        public_key_hex: Optional[str] = None,
        region: Optional[str] = None,
        client=None,
    ) -> None:
        self.key_arn = key_arn_or_id
        self.provider_type = provider_type
        self._public_key_hex = public_key_hex or ""
        self.region = region
        self.client = client

    @property
    def public_key_hex(self) -> str:
        if not self._public_key_hex:
            raise ValueError("KMS public key not yet fetched or configured.")
        return self._public_key_hex

    def sign_bytes(self, canonical_bytes: bytes) -> str:
        """
        Delegates signing to remote KMS / HSM.
        """
        if self.client is None:
            raise NotImplementedError(
                f"KMS client for {self.provider_type} not configured. "
                "Initialize with a configured boto3 or cloud client."
            )
        # Cloud KMS dispatch stub for production integrations
        raise NotImplementedError("Remote KMS signing driver call")
