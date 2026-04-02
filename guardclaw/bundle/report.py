from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def generate_html_report(summary: Dict[str, Any], ledger_sha256: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>GuardClaw Evidence Report</title>
</head>
<body>

<h1>GuardClaw Evidence Report</h1>

<p><strong>Ledger SHA-256:</strong> {_e(ledger_sha256)}</p>

<p><strong>Generated:</strong> {_e(generated_at)}</p>

<p><strong>Total Entries:</strong> {_e(summary.get("total_entries"))}</p>

<p><strong>Chain Valid:</strong> {_e(summary.get("chain_valid"))}</p>

<p><strong>Trigger:</strong> Execution Evidence Verified</p>

</body>
</html>
"""


def write_html_report(summary: Dict[str, Any], ledger_sha256: str, output_path: str | Path) -> None:
    Path(output_path).write_text(
        generate_html_report(summary, ledger_sha256),
        encoding="utf-8",
    )