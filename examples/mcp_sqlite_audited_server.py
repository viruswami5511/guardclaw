"""
examples/mcp_sqlite_audited_server.py

Reference implementation demonstrating how to add an optional --audit-log flag
to any Python SQLite Model Context Protocol (MCP) server using GuardClaw.

Run standalone or through Claude Desktop / Cursor:
    python examples/mcp_sqlite_audited_server.py --db test.db --audit-log ./db_audit_vault
"""

from __future__ import annotations
import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Optional GuardClaw import for cryptographic auditing
try:
    from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
    GUARDCLAW_AVAILABLE = True
except ImportError:
    GUARDCLAW_AVAILABLE = False


class AuditedSQLiteMCPServer:
    """
    Lightweight SQLite MCP Server with optional tamper-evident cryptographic execution logging.
    """

    def __init__(self, db_path: str, audit_path: Optional[str] = None) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.audit_path = audit_path
        self.ledger: Optional[Any] = None

        if self.audit_path:
            if not GUARDCLAW_AVAILABLE:
                raise ImportError(
                    "GuardClaw is required when --audit-log is enabled. "
                    "Install with: pip install guardclaw"
                )
            key_mgr = Ed25519KeyManager.generate()
            self.ledger = GEFLedger(
                key_manager=key_mgr,
                agent_id="sqlite-mcp-server",
                ledger_path=self.audit_path,
            )

    def execute_query(self, query: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Execute SQL query and record cryptographic intent + result if auditing is enabled.
        """
        params = params or []
        start_time = os.times()

        # 1. Record cryptographic intent before execution
        intent_envelope = None
        if self.ledger:
            intent_envelope = self.ledger.emit(
                record_type=RecordType.TOOL_CALL,
                payload={
                    "tool": "sqlite.execute_query",
                    "query": query,
                    "params": params,
                    "database": os.path.basename(self.db_path),
                },
            )

        # 2. Execute on SQLite database
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            if query.strip().upper().startswith(("SELECT", "PRAGMA")):
                rows = [dict(r) for r in cursor.fetchall()]
                result_payload = {"rows": rows, "row_count": len(rows), "status": "success"}
            else:
                self.conn.commit()
                result_payload = {
                    "rows_affected": cursor.rowcount,
                    "last_row_id": cursor.lastrowid,
                    "status": "success",
                }

            # 3. Record cryptographic execution result
            if self.ledger and intent_envelope:
                self.ledger.emit(
                    record_type=RecordType.TOOL_RESULT,
                    payload={
                        "tool": "sqlite.execute_query",
                        "status": "success",
                        "rows_affected": result_payload.get("rows_affected", len(result_payload.get("rows", []))),
                        "intent_record_id": intent_envelope.record_id,
                    },
                )
            return result_payload

        except Exception as exc:
            # 4. Record execution failure
            if self.ledger and intent_envelope:
                self.ledger.emit(
                    record_type=RecordType.TOOL_RESULT,
                    payload={
                        "tool": "sqlite.execute_query",
                        "status": "error",
                        "error_message": str(exc),
                        "intent_record_id": intent_envelope.record_id,
                    },
                )
            raise

    def close(self) -> None:
        """Close SQLite database connection and release resources."""
        if hasattr(self, "conn") and self.conn:
            self.conn.close()

    def __enter__(self) -> "AuditedSQLiteMCPServer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def main():
    parser = argparse.ArgumentParser(description="SQLite MCP Server with Tamper-Evident Audit Logging")
    parser.add_argument("--db", default=":memory:", help="Path to SQLite database file.")
    parser.add_argument("--audit-log", default=None, help="Optional directory to write tamper-evident GEF audit log.")
    args = parser.parse_args()

    server = AuditedSQLiteMCPServer(db_path=args.db, audit_path=args.audit_log)
    print(f"[*] SQLite MCP Server initialized on {args.db}")
    if args.audit_log:
        print(f"[*] Tamper-evident execution logging ENABLED at: {args.audit_log}")


if __name__ == "__main__":
    main()
