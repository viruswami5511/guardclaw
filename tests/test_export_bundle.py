import json
from pathlib import Path

from guardclaw.bundle.exporter import GEFBundleExporter
from tests.test_safe_append import _make  # reuse existing helper


def test_export_bundle_creates_artifacts(tmp_path):
    # Use existing helper to create a valid on-disk ledger
    key, ledger, ledger_path = _make(tmp_path, n=5)
    ledger.close()
    ledger_file = Path(ledger_path)

    bundle_dir = GEFBundleExporter(ledger_file).export(tmp_path)

    assert bundle_dir.exists()
    assert bundle_dir.is_dir()

    # Core bundle files
    assert (bundle_dir / "ledger.gef").exists()
    assert (bundle_dir / "manifest.json").exists()
    assert (bundle_dir / "verification.json").exists()
    assert (bundle_dir / "public_key.json").exists()
    assert (bundle_dir / "summary.json").exists()
    assert (bundle_dir / "report.html").exists()

    summary = json.loads((bundle_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["protocol_version"] == "1.0"
    assert summary["total_entries"] == 5
    assert summary["chain_valid"] is True

    html = (bundle_dir / "report.html").read_text(encoding="utf-8")
    assert "GuardClaw Evidence Report" in html
    assert "Ledger SHA-256" in html
    assert "Trigger" in html