"""
tests/test_compliance_dossier.py

Validates EU AI Act Article 12, ISO/IEC 42001, and SOC 2 Type II compliance dossier generation.
"""

import json
import tempfile
from pathlib import Path

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import RecordType
from guardclaw.bundle.compliance import ComplianceDossierGenerator


def test_compliance_dossier_generation_valid_ledger():
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        ledger = GEFLedger(key_manager=key, agent_id="compliance-agent", ledger_path=td)
        ledger.emit(RecordType.TOOL_CALL, {"tool": "db.query", "query": "SELECT * FROM audit"})
        ledger.emit(RecordType.TOOL_RESULT, {"tool": "db.query", "status": "success", "rows": 42})
        ledger.emit(RecordType.DECISION, {"decision": "approve_transaction", "confidence": 0.99})

        ledger_file = Path(td) / "ledger.jsonl"
        gen = ComplianceDossierGenerator(ledger_file)
        data = gen.build_dossier_data()

        assert data["dossier_version"] == "1.0"
        assert data["cryptographic_verification"]["chain_valid"] is True
        assert data["regulatory_mapping"]["eu_ai_act_art_12"]["status"] == "COMPLIANT"
        assert data["regulatory_mapping"]["iso_iec_42001"]["status"] == "COMPLIANT"
        assert data["regulatory_mapping"]["soc2_type2"]["status"] == "COMPLIANT"
        assert len(data["chronological_events"]) == 3

        # HTML generation test
        html_report = gen.generate_html_report()
        assert "EU AI Act" in html_report
        assert "ISO/IEC 42001" in html_report
        assert "VERIFIED COMPLIANT" in html_report

        # File export test
        out_html = Path(td) / "dossier.html"
        gen.export(out_html, format="html")
        assert out_html.exists()
        assert out_html.stat().st_size > 500
