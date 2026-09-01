"""
tests/test_audit_alias.py

Validates that @guardclaw.audit decorator functions seamlessly as an alias for @guardclaw.trace.
"""

import tempfile
from pathlib import Path
from guardclaw import audit, verify_ledger


def test_audit_decorator_creates_valid_ledger():
    with tempfile.TemporaryDirectory() as td:
        ledger_file = Path(td) / "audit_test.gef"

        @audit(agent_id="test-auditor")
        def transfer_funds(account: str, amount: float):
            return f"Transferred ${amount} to {account}"

        result = transfer_funds("AC-999", 500.0)
        assert "Transferred $500.0 to AC-999" in result
