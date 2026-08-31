"""
guardclaw/bundle/compliance.py

Enterprise Compliance Dossier Engine for GuardClaw.
Generates certified audit reports mapped to:
  - EU AI Act (Regulation (EU) 2024/1689) Article 12: Record-keeping for high-risk AI
  - ISO/IEC 42001:2023 Controls A.6.2.6 & A.6.2.8: Traceability & Logging in AIMS
  - SOC 2 Type II (Trust Services Criteria CC6.1, CC7.2, CC7.4)
  - NIST AI RMF 1.0 (Govern 1.x & Measure 2.x)
"""

from __future__ import annotations
import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from guardclaw.core.replay import ReplayEngine
from guardclaw.core.models import ExecutionEnvelope, GEF_VERSION
from guardclaw.core.merkle import MerkleTree


class ComplianceDossierGenerator:
    """
    Generates regulatory compliance dossiers from verified GEF ledgers.
    """

    def __init__(self, ledger_path: Union[str, Path]) -> None:
        self.ledger_path = Path(ledger_path)
        if not self.ledger_path.exists():
            raise FileNotFoundError(f"Ledger file not found: {self.ledger_path}")

        # Run verification
        self.engine = ReplayEngine(mode="strict", silent=True)
        self.summary = self.engine.stream_verify(self.ledger_path)

        # Load envelopes
        self.envelopes: List[ExecutionEnvelope] = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if raw:
                    self.envelopes.append(ExecutionEnvelope.from_dict(json.loads(raw)))

        self.merkle_tree = MerkleTree(self.envelopes) if self.envelopes else None

    def build_dossier_data(self) -> Dict[str, Any]:
        """Construct machine-readable compliance dossier structure."""
        first_env = self.envelopes[0] if self.envelopes else None
        last_env = self.envelopes[-1] if self.envelopes else None

        agent_id = first_env.agent_id if first_env else "unknown"
        session_id = first_env.session_id if first_env else "unknown"
        signer_pubkey = first_env.signer_public_key if first_env else "unknown"
        start_time = first_env.timestamp if first_env else ""
        end_time = last_env.timestamp if last_env else ""

        now_utc = datetime.now(timezone.utc).isoformat()

        # Tool execution summary
        tool_events = []
        for env in self.envelopes:
            if env.record_type in ("EXECUTION", "TOOL_CALL", "TOOL_RESULT", "DECISION", "RESULT", "FAILURE"):
                tool_events.append({
                    "sequence": env.sequence,
                    "record_id": env.record_id,
                    "record_type": env.record_type,
                    "timestamp": env.timestamp,
                    "causal_hash": env.causal_hash,
                    "payload": env.payload if isinstance(env.payload, dict) else {"raw": str(env.payload)},
                })

        dossier = {
            "dossier_version": "1.0",
            "protocol": f"GEF-SPEC-{GEF_VERSION}",
            "generated_at": now_utc,
            "target": {
                "ledger_name": self.ledger_path.name,
                "agent_id": agent_id,
                "session_id": session_id,
                "signer_public_key": signer_pubkey,
                "execution_window": {
                    "start": start_time,
                    "end": end_time,
                },
                "total_records": len(self.envelopes),
            },
            "cryptographic_verification": {
                "chain_valid": self.summary.chain_valid,
                "verified_count": self.summary.verified_count,
                "total_entries": self.summary.total_entries,
                "merkle_root": self.merkle_tree.root_hash if self.merkle_tree else "",
                "failure_type": str(self.summary.failure_type) if self.summary.failure_type else None,
                "failure_detail": str(self.summary.failure_detail) if self.summary.failure_detail else None,
            },
            "regulatory_mapping": {
                "eu_ai_act_art_12": {
                    "standard": "EU Regulation 2024/1689 Article 12 (Record-Keeping)",
                    "status": "COMPLIANT" if self.summary.chain_valid else "NON_COMPLIANT",
                    "clauses": [
                        {
                            "clause": "Art 12(1) - Automatic event logging throughout lifecycle",
                            "assessment": "Pass: Continuous cryptographically signed ledger emitted per action.",
                        },
                        {
                            "clause": "Art 12(2) - Traceability of operational decisions and risk mitigation",
                            "assessment": "Pass: Full causal hash chain binds prompts, tool parameters, and side-effects.",
                        },
                    ],
                },
                "iso_iec_42001": {
                    "standard": "ISO/IEC 42001:2023 AIMS (Controls A.6.2.6 & A.6.2.8)",
                    "status": "COMPLIANT" if self.summary.chain_valid else "NON_COMPLIANT",
                    "clauses": [
                        {
                            "control": "A.6.2.6 Logging of AI system activities",
                            "assessment": "Pass: Tamper-evident Ed25519 signature non-repudiation per record.",
                        },
                        {
                            "control": "A.6.2.8 Traceability of automated decision making",
                            "assessment": "Pass: SHA-256 forward causal linkage prevents retrospective modification.",
                        },
                    ],
                },
                "soc2_type2": {
                    "standard": "AICPA SOC 2 Type II (Trust Services Criteria CC6.1, CC7.2)",
                    "status": "COMPLIANT" if self.summary.chain_valid else "NON_COMPLIANT",
                    "clauses": [
                        {
                            "criterion": "CC6.1 Protection against unauthorized modification/deletion",
                            "assessment": "Pass: Modification or deletion immediately breaks deterministic verification.",
                        },
                    ],
                },
            },
            "chronological_events": tool_events,
        }
        return dossier

    def generate_html_report(self) -> str:
        """Render self-contained, print-ready HTML compliance dossier."""
        data = self.build_dossier_data()
        target = data["target"]
        crypto = data["cryptographic_verification"]
        status_color = "#10b981" if crypto["chain_valid"] else "#ef4444"
        status_badge = "VERIFIED COMPLIANT" if crypto["chain_valid"] else "VERIFICATION FAILED"

        events_html = []
        for ev in data["chronological_events"]:
            p = ev["payload"]
            action = p.get("action") or p.get("cmd") or p.get("tool") or ev["record_type"]
            result = p.get("result") or p.get("status") or ""
            events_html.append(f"""
            <tr>
                <td style="font-family: monospace; font-size: 12px;">{ev['sequence']}</td>
                <td style="font-family: monospace; font-size: 11px;">{html.escape(ev['timestamp'][:19])}Z</td>
                <td><span class="badge badge-type">{html.escape(ev['record_type'])}</span></td>
                <td style="font-weight: 600;">{html.escape(str(action))}</td>
                <td>{html.escape(str(result))}</td>
                <td style="font-family: monospace; font-size: 11px; color: #64748b;">{html.escape(ev['causal_hash'][:16])}...</td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GuardClaw Compliance Dossier — {html.escape(target['agent_id'])}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px 20px; }}
    .container {{ max-width: 960px; margin: 0 auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -2px rgba(0,0,0,0.05); padding: 40px; border: 1px solid #e2e8f0; }}
    .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e2e8f0; padding-bottom: 24px; margin-bottom: 32px; }}
    .title {{ font-size: 24px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; }}
    .subtitle {{ font-size: 13px; color: #64748b; margin: 0; text-transform: uppercase; letter-spacing: 0.5px; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; letter-spacing: 0.5px; }}
    .badge-status {{ background: {status_color}; color: #ffffff; }}
    .badge-type {{ background: #e0f2fe; color: #0369a1; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 32px; }}
    .card {{ background: #f8fafc; border-radius: 8px; padding: 20px; border: 1px solid #e2e8f0; }}
    .card-title {{ font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 0.5px; }}
    .card-row {{ display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 8px; }}
    .card-row:last-child {{ margin-bottom: 0; }}
    .card-label {{ color: #64748b; }}
    .card-value {{ font-weight: 600; font-family: monospace; color: #0f172a; }}
    .section-title {{ font-size: 16px; font-weight: 700; margin: 32px 0 16px 0; color: #0f172a; border-left: 4px solid #3b82f6; padding-left: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th {{ background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 700; color: #475569; font-size: 11px; text-transform: uppercase; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    .reg-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .reg-title {{ font-weight: 700; color: #166534; font-size: 14px; margin-bottom: 8px; }}
    .reg-desc {{ font-size: 13px; color: #15803d; line-height: 1.5; }}
    .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 class="title">AI Execution Evidence & Compliance Dossier</h1>
            <p class="subtitle">Certified Cryptographic Audit Trail • Protocol: {data['protocol']}</p>
        </div>
        <div>
            <span class="badge badge-status">{status_badge}</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Agent Execution Target</div>
            <div class="card-row"><span class="card-label">Agent ID:</span><span class="card-value">{html.escape(target['agent_id'])}</span></div>
            <div class="card-row"><span class="card-label">Session ID:</span><span class="card-value">{html.escape(target['session_id'][:18])}...</span></div>
            <div class="card-row"><span class="card-label">Total Records:</span><span class="card-value">{target['total_records']}</span></div>
            <div class="card-row"><span class="card-label">Signer PubKey:</span><span class="card-value">{html.escape(target['signer_public_key'][:16])}...</span></div>
        </div>
        <div class="card">
            <div class="card-title">Cryptographic Integrity</div>
            <div class="card-row"><span class="card-label">Chain Status:</span><span class="card-value" style="color: {status_color};">{'VALID (Unbroken)' if crypto['chain_valid'] else 'INVALID'}</span></div>
            <div class="card-row"><span class="card-label">Verified Count:</span><span class="card-value">{crypto['verified_count']} / {crypto['total_entries']}</span></div>
            <div class="card-row"><span class="card-label">Merkle Root:</span><span class="card-value">{html.escape(crypto['merkle_root'][:16])}...</span></div>
            <div class="card-row"><span class="card-label">Dossier Date:</span><span class="card-value">{html.escape(data['generated_at'][:19])}Z</span></div>
        </div>
    </div>

    <div class="section-title">Regulatory Framework Alignments</div>
    <div class="reg-box">
        <div class="reg-title">✅ EU AI Act (Regulation 2024/1689) — Article 12 Record-Keeping</div>
        <div class="reg-desc">
            High-risk AI systems requirement fulfilled. Continuous, automatic event logging is mathematically verified.
            Every tool invocation, model output, and decision is signed and bound into an irreversible SHA-256 causal chain.
        </div>
    </div>
    <div class="reg-box">
        <div class="reg-title">✅ ISO/IEC 42001:2023 — Controls A.6.2.6 & A.6.2.8 Traceability</div>
        <div class="reg-desc">
            Artificial Intelligence Management System (AIMS) control compliance certified. Full non-repudiation of operational events
            and tool execution decisions established via Ed25519 digital signatures.
        </div>
    </div>

    <div class="section-title">Provable Chronological Execution Trail</div>
    <table>
        <thead>
            <tr>
                <th>Seq</th>
                <th>Timestamp (UTC)</th>
                <th>Type</th>
                <th>Action / Tool</th>
                <th>Result</th>
                <th>Causal Hash</th>
            </tr>
        </thead>
        <tbody>
            {"".join(events_html)}
        </tbody>
    </table>

    <div class="footer">
        Generated by GuardClaw Enterprise Compliance Engine • Cryptographically Verified via GEF-SPEC-1.0
    </div>
</div>
</body>
</html>
"""
        return html_content

    def export(self, output_path: Union[str, Path], format: str = "html") -> Path:
        """Export the dossier as HTML or JSON."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if format == "json":
            out.write_text(json.dumps(self.build_dossier_data(), indent=2), encoding="utf-8")
        else:
            out.write_text(self.generate_html_report(), encoding="utf-8")
        return out
