"""
guardclaw/core/registry.py
GEF KeyRegistry — Phase 1 Trust Layer v1.0.0

Provides identity binding: key_id → public_key_hex + metadata + revocation.

TRUST MODEL:
    A KeyRegistry is the authority that binds a key_id string to a
    specific Ed25519 public key. Without this, any party can claim any
    key_id and there is no way to verify identity across sessions.

REVOCATION:
    Revoked keys are rejected at verification time. A revoked key_id
    causes SIGNER_MISMATCH at the trust layer (not the crypto layer —
    the signature may be mathematically valid but the key is untrusted).

THREAD SAFETY:
    All mutations are protected by an internal RLock.
    Safe for concurrent use within a single process.
"""

from __future__ import annotations

import threading
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timezone


@dataclass
class KeyRecord:
    key_id: str
    public_key_hex: str
    agent_id: str
    created_at: str
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "KeyRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class KeyRegistryError(Exception):
    """Base error for KeyRegistry violations."""


class KeyNotFoundError(KeyRegistryError):
    """Raised when a key_id cannot be resolved."""


class KeyRevokedError(KeyRegistryError):
    """Raised when a key_id has been revoked."""


class KeyConflictError(KeyRegistryError):
    """Raised when registering a key_id that already exists."""


class KeyMismatchError(KeyRegistryError):
    """Raised when a key_id resolves to a different public key than expected."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class KeyRegistry:
    """
    In-process KeyRegistry for GEF identity binding.

    Usage:
        registry = KeyRegistry()
        registry.register("key-001", public_key_hex, agent_id="my-agent")
        record = registry.resolve("key-001")
        registry.verify_binding("key-001", public_key_hex)  # raises on mismatch
    """

    def __init__(self) -> None:
        self._records: Dict[str, KeyRecord] = {}
        self._lock = threading.RLock()

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        key_id: str,
        public_key_hex: str,
        agent_id: str = "",
        metadata: Optional[Dict] = None,
        allow_update: bool = False,
    ) -> KeyRecord:
        """
        Register a key_id → public_key_hex binding.

        Raises KeyConflictError if key_id already registered and allow_update=False.
        """
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")
        if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
            raise ValueError("public_key_hex must be a 64-char hex string")

        with self._lock:
            if key_id in self._records and not allow_update:
                raise KeyConflictError(
                    f"key_id {key_id!r} already registered. "
                    f"Use allow_update=True to overwrite."
                )
            record = KeyRecord(
                key_id=key_id,
                public_key_hex=public_key_hex,
                agent_id=agent_id,
                created_at=_utc_now(),
                metadata=metadata or {},
            )
            self._records[key_id] = record
            return record

    # ── Resolution ────────────────────────────────────────────────────────────

    def resolve(self, key_id: str) -> KeyRecord:
        """
        Resolve key_id to its KeyRecord.

        Raises KeyNotFoundError if not registered.
        Raises KeyRevokedError if revoked.
        """
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                raise KeyNotFoundError(f"key_id {key_id!r} not found in registry")
            if record.revoked:
                raise KeyRevokedError(
                    f"key_id {key_id!r} was revoked at {record.revoked_at}. "
                    f"Reason: {record.revocation_reason or 'unspecified'}"
                )
            return record

    def resolve_public_key(self, key_id: str) -> str:
        """Convenience: resolve key_id → public_key_hex."""
        return self.resolve(key_id).public_key_hex

    # ── Binding verification ──────────────────────────────────────────────────

    def verify_binding(self, key_id: str, public_key_hex: str) -> None:
        """
        Assert that key_id is registered, not revoked, and maps to public_key_hex.

        Raises KeyNotFoundError, KeyRevokedError, or KeyMismatchError.
        """
        record = self.resolve(key_id)
        if record.public_key_hex != public_key_hex:
            raise KeyMismatchError(
                f"key_id {key_id!r} is bound to a different public key. "
                f"Expected {record.public_key_hex[:16]}... "
                f"got {public_key_hex[:16]}..."
            )

    # ── Revocation ────────────────────────────────────────────────────────────

    def revoke(self, key_id: str, reason: Optional[str] = None) -> None:
        """
        Revoke a key_id. Revoked keys fail all future verify_binding calls.

        Idempotent: revoking an already-revoked key is a no-op.
        Raises KeyNotFoundError if key_id not registered.
        """
        with self._lock:
            if key_id not in self._records:
                raise KeyNotFoundError(f"key_id {key_id!r} not found in registry")
            record = self._records[key_id]
            if not record.revoked:
                record.revoked = True
                record.revoked_at = _utc_now()
                record.revocation_reason = reason

    def is_revoked(self, key_id: str) -> bool:
        """Return True if key_id is registered and revoked. False otherwise."""
        with self._lock:
            record = self._records.get(key_id)
            return record is not None and record.revoked

    # ── Introspection ─────────────────────────────────────────────────────────

    def list_keys(self, include_revoked: bool = False) -> List[KeyRecord]:
        with self._lock:
            records = list(self._records.values())
        if not include_revoked:
            records = [r for r in records if not r.revoked]
        return records

    def has_key(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._records

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """Persist registry to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = [r.to_dict() for r in self._records.values()]
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "KeyRegistry":
        """Load registry from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Registry file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        registry = cls()
        for item in data:
            record = KeyRecord.from_dict(item)
            registry._records[record.key_id] = record
        return registry

    def __repr__(self) -> str:
        with self._lock:
            total = len(self._records)
            revoked = sum(1 for r in self._records.values() if r.revoked)
        return f"KeyRegistry(total={total}, revoked={revoked})"