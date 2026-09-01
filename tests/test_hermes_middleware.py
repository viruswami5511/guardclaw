"""
tests/test_hermes_middleware.py

Verifies that GuardClawHermesMiddleware intercepts tool lifecycle events,
emits paired intent/result envelopes, and verifies 100% cleanly.
"""

import tempfile
from pathlib import Path
from integrations.hermes.guardclaw_middleware import GuardClawHermesMiddleware


def test_hermes_middleware_lifecycle():
    with tempfile.TemporaryDirectory() as td:
        middleware = GuardClawHermesMiddleware(audit_dir=td, agent_id="hermes-coder")

        # Simulate Hermes running a terminal command tool
        intent_id = middleware.on_tool_start(
            tool_name="terminal.execute",
            tool_args={"command": "npm test"},
            call_id="call-12345",
        )
        assert intent_id is not None

        result_id = middleware.on_tool_end(
            tool_name="terminal.execute",
            result={"exit_code": 0, "output": "PASS"},
            call_id="call-12345",
        )
        assert result_id is not None

        # Verify ledger
        summary = middleware.verify()
        assert summary["chain_valid"] is True
        assert summary["verified_count"] == 3  # Genesis + Call + Result
        assert summary["verification_level"] == "FULLY_VALID"
