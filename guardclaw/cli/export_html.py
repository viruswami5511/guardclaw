from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

_GREEN = "#166534"
_RED = "#b91c1c"
_AMBER = "#b45309"
_BG = "#f8fafc"
_SURFACE = "#ffffff"
_BORDER = "#d1d5db"
_TEXT = "#111827"
_MUTED = "#6b7280"
_MONO = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
_SANS = "-apple-system, BlinkMacSystemFont, Segoe UI, Inter, Arial, sans-serif"


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def generate_html(summary: Dict[str, Any], ledger_hash: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    chain_valid = summary["chain_valid"]
    verdict_color = _GREEN if chain_valid else _RED
    verdict_text = (
        "VERIFIED — Chain intact"
        if chain_valid
        else "INVALID — Violations detected"
    )

    violations_html = ""
    if summary["violations"]:
        rows = []
        for v in summary["violations"]:
            rows.append(
                f"""
                <tr>
                  <td>{_e(v["sequence"])}</td>
                  <td>{_e(v["violation_type"])}</td>
                  <td>{_e(v["detail"])}</td>
                </tr>
                """
            )
        violations_html = f"""
        <section>
          <h2>Violations</h2>
          <table>
            <thead>
              <tr>
                <th>Sequence</th>
                <th>Type</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows)}
            </tbody>
          </table>
        </section>
        """

    timeline_rows = []
    for entry in summary["entries"]:
        timeline_rows.append(
            f"""
            <tr>
              <td>{_e(entry["sequence"])}</td>
              <td>{_e(entry["timestamp"])}</td>
              <td>{_e(entry["record_type"])}</td>
              <td title="{_e(entry["record_id"])}">{_e(entry["record_id"])}</td>
              <td title="{_e(entry["causal_hash"])}">{_e(entry["causal_hash"][:16])}…</td>
            </tr>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GuardClaw Evidence Report</title>
  <style>
    :root {{
      --bg: {_BG};
      --surface: {_SURFACE};
      --border: {_BORDER};
      --text: {_TEXT};
      --muted: {_MUTED};
      --ok: {_GREEN};
      --bad: {_RED};
      --warn: {_AMBER};
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px;
      background: var(--bg);
      color: var(--text);
      font-family: {_SANS};
      line-height: 1.5;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 28px;
    }}
    h2 {{
      margin: 0 0 12px 0;
      font-size: 20px;
    }}
    .muted {{
      color: var(--muted);
    }}
    .meta {{
      display: grid;
      grid-template-columns: 220px 1fr;
      gap: 8px 16px;
      font-size: 14px;
    }}
    .meta .label {{
      color: var(--muted);
    }}
    .mono {{
      font-family: {_MONO};
      word-break: break-all;
    }}
    .verdict {{
      border-left: 8px solid {verdict_color};
      padding: 16px 20px;
      background: var(--surface);
      border-radius: 12px;
      border-top: 1px solid var(--border);
      border-right: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }}
    .verdict-title {{
      font-size: 22px;
      font-weight: 700;
      color: {verdict_color};
      margin-bottom: 8px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(3, minmax(140px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }}
    .stat {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      background: #fcfcfd;
    }}
    .stat .k {{
      font-size: 12px;
      color: var(--muted);
    }}
    .stat .v {{
      font-size: 20px;
      font-weight: 700;
      margin-top: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .footer {{
      margin-top: 24px;
      font-size: 12px;
      color: var(--muted);
    }}
    @media (max-width: 720px) {{
      body {{ padding: 16px; }}
      .meta {{
        grid-template-columns: 1fr;
      }}
      .stats {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>GuardClaw Evidence Report</h1>
      <div class="muted">Portable, offline-verifiable execution evidence</div>
    </div>

    <div class="card">
      <div class="meta">
        <div class="label">Agent ID</div>
        <div>{_e(", ".join(summary["agent_ids"]))}</div>

        <div class="label">Ledger Path</div>
        <div class="mono">{_e(summary["ledger_path"])}</div>

        <div class="label">Generated Timestamp</div>
        <div>{_e(generated_at)}</div>

        <div class="label">Protocol Version</div>
        <div>{_e(summary["protocol_version"])}</div>

        <div class="label">GEF Version</div>
        <div>{_e(summary["gef_version"])}</div>

        <div class="label">Ledger SHA-256</div>
        <div class="mono">{_e(ledger_hash)}</div>

        <div class="label">First Timestamp</div>
        <div>{_e(summary["first_timestamp"])}</div>

        <div class="label">Last Timestamp</div>
        <div>{_e(summary["last_timestamp"])}</div>
      </div>
    </div>

    <div class="verdict">
      <div class="verdict-title">{_e(verdict_text)}</div>
      <div class="muted">
        This verdict reflects replay verification over the signed hash-chained ledger.
      </div>
      <div class="stats">
        <div class="stat">
          <div class="k">Total entries</div>
          <div class="v">{_e(summary["total_entries"])}</div>
        </div>
        <div class="stat">
          <div class="k">Valid signatures</div>
          <div class="v">{_e(summary["valid_signatures"])}</div>
        </div>
        <div class="stat">
          <div class="k">Invalid signatures</div>
          <div class="v">{_e(summary["invalid_signatures"])}</div>
        </div>
      </div>
    </div>

    {violations_html}

    <section class="card">
      <h2>Timeline</h2>
      <table>
        <thead>
          <tr>
            <th>Sequence</th>
            <th>Time</th>
            <th>Record Type</th>
            <th>Record ID</th>
            <th>Causal Hash</th>
          </tr>
        </thead>
        <tbody>
          {''.join(timeline_rows)}
        </tbody>
      </table>
    </section>

    <div class="footer">
      Generated by GuardClaw. This file is self-contained and designed for offline review.
    </div>
  </div>
</body>
</html>
"""


def write_html(summary: Dict[str, Any], ledger_hash: str, output_path: str | Path) -> None:
    Path(output_path).write_text(generate_html(summary, ledger_hash), encoding="utf-8")