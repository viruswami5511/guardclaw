"""
tests/test_mcp_sqlite_audited.py

Validates that the AuditedSQLiteMCPServer records queries, updates,
and errors into a tamper-evident GEF ledger that verifies 100% cleanly.
"""

import tempfile
from pathlib import Path
from examples.mcp_sqlite_audited_server import AuditedSQLiteMCPServer
from guardclaw import verify_ledger


def test_sqlite_mcp_audited_execution_lifecycle():
    with tempfile.TemporaryDirectory() as td:
        db_file = str(Path(td) / "app.db")
        audit_dir = str(Path(td) / "audit_vault")

        with AuditedSQLiteMCPServer(db_path=db_file, audit_path=audit_dir) as server:
            # 1. Create table
            server.execute_query("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, balance REAL)")

            # 2. Insert data
            server.execute_query("INSERT INTO users (name, balance) VALUES (?, ?)", ["Alice", 1000.0])
            server.execute_query("INSERT INTO users (name, balance) VALUES (?, ?)", ["Bob", 500.0])

            # 3. Read data
            res = server.execute_query("SELECT name, balance FROM users WHERE balance > ?", [600.0])
            assert res["row_count"] == 1
            assert res["rows"][0]["name"] == "Alice"

        # 4. Verify the cryptographic ledger
        summary = verify_ledger(audit_dir)
        assert summary["chain_valid"] is True
        assert summary["total_entries"] == 9  # Genesis + (4 queries * 2 records: intent + result)
        assert summary["verification_level"] == "FULLY_VALID"
