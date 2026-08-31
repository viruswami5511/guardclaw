"""
tests/test_export_bundle_hard.py

LOCKED v1.0 — War-test suite for Bundle Exporter.
Final hardened version for Phase 0 completion.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from guardclaw.bundle.exporter import GEFBundleExporter, BundleExportError
from guardclaw.bundle.models import BUNDLE_LEDGER_FILENAME
from guardclaw.cli import cli 
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger 
from guardclaw.core.models import RecordType


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _make_ledger(tmp_path: Path, *, n: int = 5, agent_id: str = "test-agent"):
    key = Ed25519KeyManager.generate()
    ledger = GEFLedger(key_manager=key, agent_id=agent_id, ledger_path=str(tmp_path))
    for i in range(n):
        ledger.emit("execution", {"step": i, "value": f"op-{i}"})
    ledger.close()
    return key, Path(tmp_path) / "ledger.jsonl"


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _read_lines(path: Path):
    return path.read_text(encoding="utf-8").splitlines()


def _extract_verification_view(data: dict) -> dict:
    if "guardclaw_verify" in data and isinstance(data["guardclaw_verify"], dict):
        return data["guardclaw_verify"]
    if "verification" in data and isinstance(data["verification"], dict):
        return data["verification"]
    return data


# ─────────────────────────────────────────────
# 1. BUNDLE ROUNDTRIP TESTS
# ─────────────────────────────────────────────

def test_export_bundle_roundtrip_artifacts_and_cli_consistency(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=7)

    bundle_dir = GEFBundleExporter(ledger_file).export(tmp_path)

    expected = {
        BUNDLE_LEDGER_FILENAME, 
        "manifest.json",
        "verification.json",
        "public_key.json",
        "summary.json",
        "report.html",
    }
    assert bundle_dir.exists()
    assert expected.issubset({p.name for p in bundle_dir.iterdir()})

    summary = _read_json(bundle_dir / "summary.json")
    assert summary["chain_valid"] is True
    assert summary["total_entries"] == 8

    runner = CliRunner()
    exported_ledger_path = bundle_dir / BUNDLE_LEDGER_FILENAME
    result = runner.invoke(
        cli,
        ["verify", str(exported_ledger_path), "--format", "json"],
    )
    assert result.exit_code == 0
    
    cli_data = json.loads(result.output)
    inner = cli_data.get("guardclaw_verify", cli_data)
    assert inner["chain_valid"] is True


# ─────────────────────────────────────────────
# 2. ADVERSARIAL EXPORT TESTS
# ─────────────────────────────────────────────

def test_exported_bundle_verify_fails_if_bundle_ledger_is_tampered_after_export(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=4)

    bundle_dir = GEFBundleExporter(ledger_file).export(tmp_path)
    exported_ledger = bundle_dir / BUNDLE_LEDGER_FILENAME

    # Tamper with the last record
    lines = _read_lines(exported_ledger)
    last = json.loads(lines[-1])
    last["payload"]["step"] = 999999 
    lines[-1] = json.dumps(last, separators=(",", ":"))
    exported_ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["verify", str(exported_ledger), "--format", "json"],
    )

    # The CLI must exit with non-zero on tamper
    assert result.exit_code != 0
    
    cli_data = json.loads(result.output)
    inner = cli_data.get("guardclaw_verify", cli_data)

    # PROTOCOL INTEGRITY CHECK
    # We verify that the system correctly flagged the chain as invalid.
    # We also check that a failure_type was reported (LOCKED Spec Requirement).
    assert inner["chain_valid"] is False
    assert inner["failure_type"] is not None
    assert inner["verification_level"] == "INVALID"


def test_export_refuses_preexisting_tampered_source_ledger(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=3)

    lines = _read_lines(ledger_file)
    first = json.loads(lines[0])
    first["payload"]["tamper"] = True
    lines[0] = json.dumps(first, separators=(",", ":"))
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(BundleExportError):
        GEFBundleExporter(ledger_file).export(tmp_path)


# ─────────────────────────────────────────────
# 3. PATH RESOLUTION TESTS
# ─────────────────────────────────────────────

def test_export_to_explicit_gcbundle_path_creates_that_directory(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=2)
    out = tmp_path / "custom-output.gcbundle"

    bundle_dir = GEFBundleExporter(ledger_file).export(out)

    assert bundle_dir == out
    assert bundle_dir.exists()
    assert (bundle_dir / BUNDLE_LEDGER_FILENAME).exists()


def test_export_to_plain_directory_creates_subdir_and_cli_export_mentions_shareable_bundle(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=2)
    target_dir = tmp_path / "exports"
    target_dir.mkdir()

    bundle_dir = GEFBundleExporter(ledger_file).export(target_dir)
    assert bundle_dir.parent == target_dir
    assert bundle_dir.name.endswith(".gcbundle")

    runner = CliRunner()
    result = runner.invoke(cli, ["export", str(ledger_file), "--output", str(target_dir)])
    assert result.exit_code == 0
    assert ".gcbundle" in result.output
