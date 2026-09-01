"""
tests/test_daemon_ipc.py

Validates the isolated Out-of-Process Signing Daemon and Zero-Key Client.
Tests IPC socket streaming, zero-key agent event emission, head synchronization,
and Merkle root computation over RPC.
"""

import tempfile
import time
from pathlib import Path

from guardclaw.daemon.service import GuardClawDaemon
from guardclaw.daemon.client import DaemonClient
from guardclaw.core.models import RecordType
from guardclaw.core.replay import ReplayEngine


def test_daemon_lifecycle_and_zero_key_client():
    port = 19443  # Dedicated test port
    with tempfile.TemporaryDirectory() as td:
        daemon = GuardClawDaemon(
            ledger_path=td,
            agent_id="enterprise-agent",
            host="127.0.0.1",
            port=port,
        )
        daemon.start(blocking=False)
        time.sleep(0.1)  # Allow socket bind

        try:
            with DaemonClient(host="127.0.0.1", port=port) as client:
                # 1. Ping daemon
                ping_res = client.ping()
                assert ping_res["status"] == "online"
                assert ping_res["agent_id"] == "enterprise-agent"
                assert ping_res["signer_public_key"] == daemon.key_provider.public_key_hex

                # 2. Emit records from zero-key client
                env1 = client.emit(
                    record_type=RecordType.TOOL_CALL,
                    payload={"tool": "wire_transfer", "amount_usd": 150000},
                )
                assert env1.sequence == 1
                assert env1.agent_id == "enterprise-agent"
                assert env1.signature

                env2 = client.emit(
                    record_type=RecordType.TOOL_RESULT,
                    payload={"status": "confirmed", "tx_id": "0xabc123"},
                )
                assert env2.sequence == 2

                # 3. Query head and Merkle root over RPC
                head = client.get_head()
                assert head.sequence == 2
                assert head.record_id == env2.record_id

                root = client.get_merkle_root()
                assert len(root) == 64

            # 4. Cryptographic Replay Verification of the written ledger
            ledger_file = Path(td) / "ledger.jsonl"
            summary = ReplayEngine(mode="strict", silent=True).stream_verify(ledger_file)
            assert summary.chain_valid is True
            assert summary.total_entries == 3  # Genesis + 2 tool calls
        finally:
            daemon.stop()
