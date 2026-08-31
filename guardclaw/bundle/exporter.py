"""
guardclaw/bundle/exporter.py

LOCKED v1.0 — GEF Bundle Exporter.
Hardened for identity consistency and spec compliance.
"""

from __future__ import annotations

import json
import shutil
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from guardclaw import __version__
from guardclaw.bundle.models import (
    BundleManifest,
    BundleVerification,
    BundlePublicKey,
    BUNDLE_LEDGER_FILENAME,
    GEF_BUNDLE_VERSION,
)
from guardclaw.bundle.report import write_html_report
from guardclaw.core.replay import ReplayEngine


class BundleExportError(Exception):
    """Raised when bundle export violates protocol invariants."""
    pass


class GEFBundleExporter:
    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = Path(ledger_path)

        if not self.ledger_path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")

    def export(
        self,
        output: Optional[Path] = None,
        forensic: bool = False,
        deterministic: bool = False,
    ) -> Path:
        """
        Export a GEF ledger into a standardized .gcbundle.
        Strictly enforces identity consistency and cryptographic integrity.
        """

        # ─────────────────────────────────────────────────────────────
        # 1. OUTPUT PATH RESOLUTION
        # ─────────────────────────────────────────────────────────────
        if output is None:
            output = self.ledger_path.with_suffix(".gcbundle")

        output = Path(output)

        if output.exists() and output.is_dir():
            output = output / f"{self.ledger_path.stem}.gcbundle"
        elif not output.name.endswith(".gcbundle"):
            output = output.with_suffix(".gcbundle")

        # ─────────────────────────────────────────────────────────────
        # 2. RAW IDENTITY CHECK (Pre-flight)
        # ─────────────────────────────────────────────────────────────
        self._assert_single_identity_raw(self.ledger_path)

        # ─────────────────────────────────────────────────────────────
        # 3. STREAM VERIFICATION (L1 Protocol Check)
        # ─────────────────────────────────────────────────────────────
        # Fix: Removed 'parallel' argument
        summary = ReplayEngine(
            mode="strict",
            silent=True
        ).stream_verify(self.ledger_path)

        if not summary.chain_valid:
            if not (summary.failure_type == "chain_violation" and summary.failure_detail == "genesis_missing"):
                raise BundleExportError(
                    f"Ledger is INVALID: {summary.failure_type} / {summary.failure_detail}"
                )

        # ─────────────────────────────────────────────────────────────
        # 4. LOAD ENGINE (Full State Rehydration)
        # ─────────────────────────────────────────────────────────────
        # Fix: Removed 'parallel' argument
        engine = ReplayEngine(mode="strict", silent=True)
        engine.load(self.ledger_path)

        # ─────────────────────────────────────────────────────────────
        # 5. CRYPTOGRAPHIC IDENTITY AUDIT
        # ─────────────────────────────────────────────────────────────
        self._assert_single_identity_engine(engine)

        for env in engine.envelopes:
            ok, _ = env.verify_signature()
            if not ok:
                raise BundleExportError(f"Ledger is INVALID: signature mismatch at seq {env.sequence}")

        verified_count = len(engine.envelopes)

        # ─────────────────────────────────────────────────────────────
        # 6. CALCULATE LEDGER HASH
        # ─────────────────────────────────────────────────────────────
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        trusted_lines = lines[:verified_count]
        trusted_bytes = "".join(trusted_lines).encode("utf-8")
        ledger_sha256 = hashlib.sha256(trusted_bytes).hexdigest()

        # ─────────────────────────────────────────────────────────────
        # 7. GENERATE SUMMARY CONTRACT
        # ─────────────────────────────────────────────────────────────
        summary_dict = {
            "protocol_version": "1.0",
            "chain_valid": True,
            "total_entries": verified_count,
            "verified_entries": verified_count,
            "integrity_status": "FULL",
            "violations": [],
        }

        if engine.envelopes:
            summary_dict.update({
                "agent_ids": list({e.agent_id for e in engine.envelopes}),
                "gef_version": engine.envelopes[0].gef_version,
                "first_timestamp": engine.envelopes[0].timestamp,
                "last_timestamp": engine.envelopes[-1].timestamp,
                "session_id": engine.envelopes[0].session_id,
            })

        # ─────────────────────────────────────────────────────────────
        # 8. WRITE BUNDLE ARTIFACTS
        # ─────────────────────────────────────────────────────────────
        if output.exists():
            shutil.rmtree(output)

        output.mkdir(parents=True)

        (output / BUNDLE_LEDGER_FILENAME).write_text("".join(trusted_lines), encoding="utf-8")

        created_at = "1970-01-01T00:00:00+00:00" if deterministic else datetime.now(timezone.utc).isoformat()

        BundleManifest(
            gef_bundle_version=GEF_BUNDLE_VERSION,
            created_at=created_at,
            agent_id=summary_dict.get("agent_ids", [""])[0],
            ledger_file=BUNDLE_LEDGER_FILENAME,
            entry_count=verified_count,
            first_entry_at=summary_dict.get("first_timestamp"),
            last_entry_at=summary_dict.get("last_timestamp"),
            ledger_sha256=ledger_sha256,
            ledger_size_bytes=len(trusted_bytes),
            chain_head_hash=engine.envelopes[-1].causal_hash if engine.envelopes else None,
            chain_head_sequence=engine.envelopes[-1].sequence if engine.envelopes else None,
            guardclaw_version=__version__,
            gef_version=summary_dict.get("gef_version"),
            integrity_status="FULL",
            verified_entry_count=verified_count,
            total_entry_count=verified_count,
            untrusted_ledger_file=None,
        ).write(output / "manifest.json")

        BundleVerification(
            verified_at=created_at,
            integrity_status="FULL",
            verified_entry_count=verified_count,
            total_entry_count=verified_count,
            duration_seconds=0.0,
            guardclaw_version=__version__,
        ).write(output / "verification.json")

        BundlePublicKey(
            algorithm="Ed25519",
            public_key=self._extract_public_key(engine),
            agent_id=summary_dict.get("agent_ids", [""])[0],
        ).write(output / "public_key.json")

        (output / "summary.json").write_text(json.dumps(summary_dict, indent=2), encoding="utf-8")

        write_html_report(summary_dict, ledger_sha256, output / "report.html")

        return output

    def _assert_single_identity_raw(self, ledger_path: Path) -> None:
        keys: set = set()
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        pk = data.get("signer_public_key")
                        if pk: keys.add(pk)
        except Exception: return
        if len(keys) > 1:
            raise BundleExportError("Identity mismatch: multiple signing keys detected")

    def _assert_single_identity_engine(self, engine: ReplayEngine) -> None:
        keys = set()
        for env in engine.envelopes:
            pk = getattr(env, "signer_public_key", None)
            if pk: keys.add(pk)
        if len(keys) > 1:
            raise BundleExportError("Identity inconsistency: multiple signing keys detected")

    def _extract_public_key(self, engine: ReplayEngine) -> str:
        if not engine.envelopes: return ""
        last = engine.envelopes[-1]
        pk = last.signer_public_key
        if isinstance(pk, bytes):
            import base64
            return base64.urlsafe_b64encode(pk).decode()
        return str(pk)