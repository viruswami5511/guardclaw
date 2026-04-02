from __future__ import annotations

import json
import shutil
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
from guardclaw.core.summary import build_summary_from_engine


class BundleExportError(Exception):
    pass


class GEFBundleExporter:
    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = Path(ledger_path)

        if not self.ledger_path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")

    def export(self, output: Optional[Path] = None, forensic: bool = False) -> Path:
        # -------------------------
        # Resolve output path
        # -------------------------
        if output is None:
            output = self.ledger_path.with_suffix(".gcbundle")

        output = Path(output)

        if output.exists() and output.is_dir():
            output = output / f"{self.ledger_path.stem}.gcbundle"
        elif not output.name.endswith(".gcbundle"):
            output = output.with_suffix(".gcbundle")

        # -------------------------
        # Verification
        # -------------------------
        t_start = time.perf_counter()

        engine = ReplayEngine(parallel=False, silent=True)
        engine.load(self.ledger_path)

        # ✅ Identity check (NO file read)
        self._assert_single_identity_engine(engine)

        replay = engine.verify()

        if replay.violations:
            raise BundleExportError("Ledger is INVALID")

        verified_count = len(engine.envelopes)

        # -------------------------
        # Read ledger ONCE
        # -------------------------
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        trusted_lines = lines[:verified_count]

        trusted_bytes = "".join(trusted_lines).encode("utf-8")
        ledger_sha256 = hashlib.sha256(trusted_bytes).hexdigest()

        # -------------------------
        # Summary
        # -------------------------
        summary_engine = ReplayEngine(parallel=False, silent=True)
        summary_engine.envelopes = engine.envelopes

        summary = build_summary_from_engine(
            summary_engine,
            self.ledger_path,
            verification_summary=replay,
        )

        # -------------------------
        # Write bundle
        # -------------------------
        if output.exists():
            shutil.rmtree(output)

        output.mkdir(parents=True)

        (output / BUNDLE_LEDGER_FILENAME).write_text(
            "".join(trusted_lines),
            encoding="utf-8",
        )

        now = datetime.now(timezone.utc).isoformat()

        BundleManifest(
            gef_bundle_version=GEF_BUNDLE_VERSION,
            created_at=now,
            agent_id=summary["agent_ids"][0] if summary["agent_ids"] else "",
            ledger_file=BUNDLE_LEDGER_FILENAME,
            entry_count=verified_count,
            first_entry_at=summary["first_timestamp"],
            last_entry_at=summary["last_timestamp"],
            ledger_sha256=ledger_sha256,
            ledger_size_bytes=len(trusted_bytes),
            chain_head_hash=None,
            chain_head_sequence=None,
            guardclaw_version=__version__,
            gef_version=summary["gef_version"],
            integrity_status="FULL",
            verified_entry_count=verified_count,
            total_entry_count=verified_count,
            untrusted_ledger_file=None,
        ).write(output / "manifest.json")

        BundleVerification(
            verified_at=now,
            integrity_status="FULL",
            verified_entry_count=verified_count,
            total_entry_count=verified_count,
            duration_seconds=round(time.perf_counter() - t_start, 3),
            guardclaw_version=__version__,
        ).write(output / "verification.json")

        BundlePublicKey(
            algorithm="Ed25519",
            public_key=self._extract_public_key(engine),
            agent_id=summary["agent_ids"][0] if summary["agent_ids"] else "",
        ).write(output / "public_key.json")

        (output / "summary.json").write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )

        write_html_report(summary, ledger_sha256, output / "report.html")

        return output

    # =========================
    # HELPERS
    # =========================
    def _assert_single_identity_engine(self, engine: ReplayEngine):
        keys = set()

        for env in engine.envelopes:
            pk = getattr(env, "signer_public_key", None)
            if pk:
                keys.add(pk)

        if len(keys) > 1:
            raise BundleExportError(
                "Identity inconsistency: multiple signing keys detected"
            )

    def _extract_public_key(self, engine: ReplayEngine) -> str:
        if not engine.envelopes:
            return ""

        last = engine.envelopes[-1]
        pk = last.signer_public_key

        if isinstance(pk, bytes):
            import base64
            return base64.urlsafe_b64encode(pk).decode()

        return str(pk)