"""
guardclaw/core/kms.py

Pluggable Key Management & Hardware Security Isolation Layer.
Enables GuardClaw signing keys to reside outside the agent process/container,
such as in AWS KMS, Azure Key Vault, HashiCorp Vault, or an isolated enclave.
"""

from __future__ import annotations
import abc
import base64
from pathlib import Path
from typing import Any, Dict, Optional, Union

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
        return self._key_manager.sign(canonical_bytes)


class AWSKMSKeyProvider(KeyProvider):
    """
    Native AWS KMS Hardware Security Module (HSM) signing provider.
    The agent runtime sends canonical payload digests to AWS KMS,
    and KMS signs inside the FIPS 140-3 Level 3 hardware boundary.
    """

    def __init__(
        self,
        key_id: str,
        region_name: Optional[str] = None,
        signing_algorithm: str = "ED25519_RAW",
        boto_client: Optional[Any] = None,
    ) -> None:
        self.key_id = key_id
        self.signing_algorithm = signing_algorithm
        self.region_name = region_name
        self._cached_pubkey_hex: Optional[str] = None

        if boto_client is not None:
            self.client = boto_client
        else:
            try:
                import boto3
                self.client = boto3.client("kms", region_name=region_name)
            except ImportError:
                raise ImportError(
                    "boto3 is required for AWSKMSKeyProvider. "
                    "Install with: pip install boto3"
                )

    @property
    def public_key_hex(self) -> str:
        if self._cached_pubkey_hex is None:
            res = self.client.get_public_key(KeyId=self.key_id)
            pub_bytes = res["PublicKey"]
            # Extract raw 32-byte Ed25519 key if wrapped in SubjectPublicKeyInfo
            if len(pub_bytes) == 32:
                raw_bytes = pub_bytes
            elif len(pub_bytes) > 32:
                # Standard DER SubjectPublicKeyInfo prefix for Ed25519 is 12 bytes
                raw_bytes = pub_bytes[-32:]
            else:
                raw_bytes = pub_bytes
            self._cached_pubkey_hex = raw_bytes.hex()
        return self._cached_pubkey_hex

    def sign_bytes(self, canonical_bytes: bytes) -> str:
        response = self.client.sign(
            KeyId=self.key_id,
            Message=canonical_bytes,
            MessageType="RAW",
            SigningAlgorithm=self.signing_algorithm,
        )
        sig_bytes = response["Signature"]
        return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")


class VaultKeyProvider(KeyProvider):
    """
    HashiCorp Vault Transit Engine Hardware Signing Provider.
    """

    def __init__(
        self,
        vault_url: str,
        token: str,
        key_name: str,
        mount_point: str = "transit",
        hvac_client: Optional[Any] = None,
    ) -> None:
        self.vault_url = vault_url.rstrip("/")
        self.token = token
        self.key_name = key_name
        self.mount_point = mount_point
        self.client = hvac_client
        self._cached_pubkey_hex: Optional[str] = None

    @property
    def public_key_hex(self) -> str:
        if self._cached_pubkey_hex is None:
            if self.client:
                read_res = self.client.secrets.transit.read_key(
                    name=self.key_name, mount_point=self.mount_point
                )
                keys = read_res.get("data", {}).get("keys", {})
                latest_ver = max(map(int, keys.keys()))
                pub_b64 = keys[str(latest_ver)]["public_key"]
                self._cached_pubkey_hex = base64.b64decode(pub_b64).hex()
            else:
                raise ValueError("Vault client not initialized.")
        return self._cached_pubkey_hex

    def sign_bytes(self, canonical_bytes: bytes) -> str:
        if not self.client:
            raise ValueError("Vault client not initialized.")
        b64_payload = base64.b64encode(canonical_bytes).decode("ascii")
        res = self.client.secrets.transit.sign_data(
            name=self.key_name,
            hash_input=b64_payload,
            mount_point=self.mount_point,
            signature_algorithm="ed25519",
        )
        # Vault returns vault:v1:<base64_sig>
        vault_sig = res["data"]["signature"]
        raw_b64 = vault_sig.split(":")[-1]
        sig_raw = base64.b64decode(raw_b64)
        return base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")


class MockKMSKeyProvider(KeyProvider):
    """
    In-memory isolated mock KMS provider for unit testing & CI pipelines.
    Simulates remote cloud KMS API with Ed25519 hardware key isolation.
    """

    def __init__(self, key_id: str = "arn:aws:kms:us-east-1:123456789012:key/mock-ed25519-key") -> None:
        self.key_id = key_id
        self._key_manager = Ed25519KeyManager.generate()
        self.call_count = 0

    @property
    def public_key_hex(self) -> str:
        return self._key_manager.public_key_hex

    def sign_bytes(self, canonical_bytes: bytes) -> str:
        self.call_count += 1
        return self._key_manager.sign(canonical_bytes)
