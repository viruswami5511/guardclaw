"""
guardclaw/bundle/models.py

GEF Bundle data models.

A .gcbundle folder is the portable, auditor-ready artifact produced by
`guardclaw export`. It packages the ledger alongside pre-computed
verification metadata so the bundle can be inspected without running
verification again.

Bundle layout:
    <name>.gcbundle/
        ledger.gef              ← trusted artifact (content-addressed by ledger_sha256)
        ledger_untrusted.gef    ← optional untrusted remainder for forensic review
        manifest.json           ← bundle identity + stats
        verification.json       ← verification result at export time (informational only)
        public_key.json         ← Ed25519 public key extracted FROM the ledger

TRUST MODEL (non-negotiable):
    verification.json is INFORMATIONAL.
    ledger.gef is the SOURCE OF TRUTH.
    Any verifier must re-verify ledger.gef directly.
    Pre-computed results are provided as a convenience layer only.

KEY CONSISTENCY RULE:
    public_key.json is extracted FROM the ledger (signer_public_key field),
    NOT generated independently. This prevents mismatched identity and
    ensures the key is the one that actually signed the chain.

GEF-SPEC-1.0 aligned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

GEF_BUNDLE_VERSION = "1.1"
BUNDLE_LEDGER_FILENAME = "ledger.gef"
BUNDLE_UNTRUSTED_LEDGER_FILENAME = "ledger_untrusted.gef"


@dataclass
class BundleManifest:
    """
    Bundle identity and ledger statistics.

    Written to manifest.json at export time. Enables quick inspection
    without re-reading the ledger.
    """
    gef_bundle_version: str
    created_at: str
    agent_id: str
    ledger_file: str
    entry_count: int
    first_entry_at: Optional[str]
    last_entry_at: Optional[str]
    ledger_sha256: str
    ledger_size_bytes: int
    chain_head_hash: Optional[str]
    chain_head_sequence: Optional[int]
    guardclaw_version: str
    gef_version: Optional[str]

    integrity_status: str                    # "FULL" | "PARTIAL"
    verified_entry_count: int
    total_entry_count: int
    untrusted_ledger_file: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )

    @classmethod
    def from_path(cls, path: Path) -> "BundleManifest":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class BundleVerification:
    """
    Verification result snapshot captured at export time.

    Written to verification.json. INFORMATIONAL ONLY — not a trust anchor.
    Any consumer must re-verify ledger.gef to establish independent trust.
    """
    verified_at: str
    integrity_status: str                    # "FULL" | "PARTIAL"
    verified_entry_count: int
    total_entry_count: int
    duration_seconds: float
    guardclaw_version: str

    failure_sequence: Optional[int] = None
    failure_type: Optional[str] = None
    failure_detail: Optional[str] = None
    integrity_boundary_hash: Optional[str] = None
    boundary_sequence: Optional[int] = None
    violations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )

    @classmethod
    def from_path(cls, path: Path) -> "BundleVerification":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class BundlePublicKey:
    """
    Ed25519 public key extracted from the ledger.

    Written to public_key.json.
    """
    algorithm: str
    public_key: str
    agent_id: str

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )

    @classmethod
    def from_path(cls, path: Path) -> "BundlePublicKey":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)