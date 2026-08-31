"""
tests/test_cli_extended.py

Validates extended CLI commands:
- guardclaw dossier
- guardclaw prove-inclusion
- guardclaw verify-inclusion
"""

import json
import tempfile
from pathlib import Path
from click.testing import CliRunner

from guardclaw.cli import cli
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import RecordType


def test_cli_dossier_export():
    runner = CliRunner()
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        ledger = GEFLedger(key_manager=key, agent_id="cli-agent", ledger_path=td)
        ledger.emit(RecordType.EXECUTION, {"step": "db_query"})
        ledger_path = str(Path(td) / "ledger.jsonl")
        out_html = str(Path(td) / "audit_report.html")

        res = runner.invoke(cli, ["dossier", ledger_path, "--output", out_html, "--format", "html"])
        assert res.exit_code == 0
        assert Path(out_html).exists()
        assert "COMPLIANT" in res.output


def test_cli_merkle_inclusion_prove_and_verify():
    runner = CliRunner()
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        ledger = GEFLedger(key_manager=key, agent_id="merkle-agent", ledger_path=td)
        env = ledger.emit(RecordType.EXECUTION, {"action": "critical_decision"})
        ledger_path = str(Path(td) / "ledger.jsonl")

        # Prove inclusion
        res = runner.invoke(cli, ["prove-inclusion", ledger_path, "--record-id", env.record_id, "--format", "json"])
        assert res.exit_code == 0
        proof_data = json.loads(res.output)
        assert proof_data["record_id"] == env.record_id

        # Save proof file
        proof_file = Path(td) / "proof.json"
        proof_file.write_text(res.output, encoding="utf-8")

        # Verify inclusion
        res_v = runner.invoke(cli, ["verify-inclusion", str(proof_file)])
        assert res_v.exit_code == 0
        assert "Inclusion Proof Valid" in res_v.output
