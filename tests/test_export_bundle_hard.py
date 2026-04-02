# tests/test_export_bundle_hard.py
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from guardclaw.bundle.exporter import GEFBundleExporter, BundleExportError
from guardclaw.cli import cli
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import RecordType


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


def test_export_bundle_roundtrip_artifacts_and_cli_consistency(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=7)

    bundle_dir = GEFBundleExporter(ledger_file).export(tmp_path)

    expected = {
        "ledger.gef",
        "manifest.json",
        "verification.json",
        "public_key.json",
        "summary.json",
        "report.html",
    }
    assert bundle_dir.exists()
    assert bundle_dir.is_dir()
    assert expected.issubset({p.name for p in bundle_dir.iterdir()})

    summary          = _read_json(bundle_dir / "summary.json")
    verification_raw = _read_json(bundle_dir / "verification.json")
    verification     = _extract_verification_view(verification_raw)
    manifest         = _read_json(bundle_dir / "manifest.json")
    public_key       = _read_json(bundle_dir / "public_key.json")

    assert summary["chain_valid"] is True
    assert summary["total_entries"] == 7
    assert isinstance(summary["violations"], list)
    assert not summary["violations"]

    assert isinstance(verification, dict) and verification
    assert isinstance(manifest, dict) and manifest
    assert isinstance(public_key, dict) and public_key

    # ── validity field check (handles all shapes GuardClaw emits) ──────────
    if "chain_valid" in verification:
        assert verification["chain_valid"] is True
    elif "ledger_valid" in verification:
        assert verification["ledger_valid"] is True
    elif "integrity_status" in verification:
        assert verification["integrity_status"] in ("FULL", "VALID"), (
            f"Unexpected integrity_status: {verification['integrity_status']}"
        )
    else:
        pytest.fail(
            f"verification.json missing expected validity field: {verification}"
        )

    # ── entry count check (handles all shapes) ────────────────────────────
    if "total_entries" in verification:
        assert verification["total_entries"] == 7
    elif "original_count" in verification:
        assert verification["original_count"] == 7
    elif "verified_entry_count" in verification:
        assert verification["verified_entry_count"] == 7
    elif "total_entry_count" in verification:
        assert verification["total_entry_count"] == 7

    # ── CLI verify consistency check ──────────────────────────────────────
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["verify", str(bundle_dir / "ledger.gef"), "--format", "json"],
    )
    assert result.exit_code == 0, result.output

    cli_data = json.loads(result.output)
    inner    = cli_data["guardclaw_verify"]

    assert inner["chain_valid"] is True
    assert inner["ledger_valid"] is True
    assert inner["total_entries"] == 7
    assert inner["valid_signatures"] == 7
    assert inner["invalid_signatures"] == 0
    assert inner["violation_count"] == 0
    assert inner["violations"] == []

    assert inner["chain_valid"] == summary["chain_valid"]
    assert inner["total_entries"] == summary["total_entries"]

    # ── CLI export smoke-test (CliRunner — no subprocess needed) ─────────
    export_result = runner.invoke(cli, ["export", str(ledger_file)])
    assert export_result.exit_code == 0, export_result.output
    assert "bundle" in export_result.output.lower()


def test_exported_bundle_verify_fails_if_bundle_ledger_is_tampered_after_export(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=4)

    bundle_dir = GEFBundleExporter(ledger_file).export(tmp_path)
    exported_ledger = bundle_dir / "ledger.gef"

    lines = _read_lines(exported_ledger)
    assert len(lines) == 4

    last = json.loads(lines[-1])
    last["payload"]["step"] = 999999
    lines[-1] = json.dumps(last, separators=(",", ":"))
    exported_ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["verify", str(exported_ledger), "--format", "json"],
    )

    assert result.exit_code != 0
    cli_data = json.loads(result.output)
    inner = cli_data["guardclaw_verify"]

    assert inner["chain_valid"] is False or inner["violation_count"] > 0
    assert inner["invalid_signatures"] > 0 or inner["violation_count"] > 0
    assert inner["violations"]


def test_export_refuses_preexisting_tampered_source_ledger(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=3)

    lines = _read_lines(ledger_file)
    assert len(lines) == 3

    first = json.loads(lines[0])
    first["payload"]["step"] = 12345
    lines[0] = json.dumps(first, separators=(",", ":"))
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(BundleExportError):
        GEFBundleExporter(ledger_file).export(tmp_path)


def test_export_refuses_mixed_signing_identities_in_single_input_ledger(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    key_a = Ed25519KeyManager.generate()
    key_b = Ed25519KeyManager.generate()

    ledger_a = GEFLedger(key_manager=key_a, agent_id="agent-A", ledger_path=str(dir_a))
    ledger_b = GEFLedger(key_manager=key_b, agent_id="agent-B", ledger_path=str(dir_b))

    ledger_a.emit("execution", {"step": 1, "source": "A"})
    ledger_b.emit("execution", {"step": 2, "source": "B"})

    ledger_a.close()
    ledger_b.close()

    lines_a = _read_lines(dir_a / "ledger.jsonl")
    lines_b = _read_lines(dir_b / "ledger.jsonl")
    mixed_path = tmp_path / "mixed.jsonl"
    mixed_path.write_text("\n".join(lines_a + lines_b) + "\n", encoding="utf-8")

    with pytest.raises(BundleExportError) as exc:
        GEFBundleExporter(mixed_path).export(tmp_path)

    assert "Identity" in str(exc.value) or "sign" in str(exc.value).lower()


def test_export_to_explicit_gcbundle_path_creates_that_directory(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=2)
    out = tmp_path / "custom-output.gcbundle"

    bundle_dir = GEFBundleExporter(ledger_file).export(out)

    assert bundle_dir == out
    assert bundle_dir.exists()
    assert (bundle_dir / "ledger.gef").exists()
    assert (bundle_dir / "summary.json").exists()


def test_export_to_plain_directory_creates_subdir_and_cli_export_mentions_shareable_bundle(tmp_path):
    _, ledger_file = _make_ledger(tmp_path, n=2)

    target_dir = tmp_path / "exports"
    target_dir.mkdir()

    bundle_dir = GEFBundleExporter(ledger_file).export(target_dir)
    assert bundle_dir.parent == target_dir
    assert bundle_dir.name.endswith(".gcbundle")

    runner = CliRunner()
    result = runner.invoke(cli, ["export", str(ledger_file), "--output", str(target_dir)])
    assert result.exit_code == 0, result.output
    assert "Export" in result.output or "Bundle" in result.output
    assert ".gcbundle" in result.output


def test_cli_export_fails_cleanly_on_missing_ledger(tmp_path):
    missing = tmp_path / "missing.jsonl"
    runner = CliRunner()

    result = runner.invoke(cli, ["export", str(missing)])
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower() or "error" in result.output.lower()