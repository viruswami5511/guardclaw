"""
guardclaw/daemon/service.py

High-Performance Out-of-Process Signing Daemon for GuardClaw.
Isolates cryptographic private keys and cloud KMS credentials completely
outside of agent runtime processes/containers.
"""

from __future__ import annotations
import json
import logging
import socket
import socketserver
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.kms import KeyProvider, LocalKeyProvider
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import ExecutionEnvelope, RecordType
from guardclaw.core.merkle import MerkleTree

_log = logging.getLogger(__name__)


class _DaemonTCPHandler(socketserver.StreamRequestHandler):
    """Line-delimited JSON-RPC 2.0 Request Handler."""

    def handle(self) -> None:
        daemon_server: GuardClawDaemon = self.server.daemon_instance  # type: ignore

        for line in self.rfile:
            raw = line.decode("utf-8").strip()
            if not raw:
                continue
            try:
                req = json.loads(raw)
                req_id = req.get("id")
                method = req.get("method")
                params = req.get("params", {})

                res_data = daemon_server.dispatch(method, params)
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": res_data,
                }
            except Exception as exc:
                _log.warning("Daemon dispatch error: %s", exc)
                response = {
                    "jsonrpc": "2.0",
                    "id": req.get("id") if "req" in locals() and isinstance(req, dict) else None,
                    "error": {"code": -32603, "message": str(exc)},
                }

            out_bytes = (json.dumps(response) + "\n").encode("utf-8")
            self.wfile.write(out_bytes)
            self.wfile.flush()


class GuardClawDaemon:
    """
    Enterprise Signing Daemon service.
    """

    def __init__(
        self,
        ledger_path: Union[str, Path],
        agent_id: str = "daemon-service",
        key_provider: Optional[KeyProvider] = None,
        host: str = "127.0.0.1",
        port: int = 9443,
    ) -> None:
        self.ledger_path = Path(ledger_path)
        self.agent_id = agent_id
        self.host = host
        self.port = port
        self.start_time = time.time()

        if key_provider is None:
            self.key_manager = Ed25519KeyManager.generate()
            self.key_provider: KeyProvider = LocalKeyProvider(self.key_manager)
        elif isinstance(key_provider, LocalKeyProvider):
            self.key_manager = key_provider.key_manager
            self.key_provider = key_provider
        else:
            self.key_provider = key_provider
            self.key_manager = Ed25519KeyManager.generate()

        self.ledger = GEFLedger(
            key_manager=self.key_manager,
            agent_id=self.agent_id,
            ledger_path=str(self.ledger_path),
        )

        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None

    def dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "ping":
            return {
                "status": "online",
                "uptime": time.time() - self.start_time,
                "signer_public_key": self.key_provider.public_key_hex,
                "agent_id": self.agent_id,
                "entry_count": self.ledger.entry_count,
            }

        elif method == "emit":
            rec_type = params.get("record_type", RecordType.EXECUTION)
            payload = params.get("payload", {})
            key_id = params.get("key_id")
            env = self.ledger.emit(record_type=rec_type, payload=payload, key_id=key_id)
            return env.to_dict()

        elif method == "get_head":
            head = self.ledger.head
            return head.to_dict() if head else {}

        elif method == "get_root":
            tree = MerkleTree(self.ledger.entries)
            return {
                "root_hash": tree.root_hash,
                "total_leaves": len(self.ledger.entries),
            }

        else:
            raise ValueError(f"Unknown RPC method: {method}")

    def start(self, blocking: bool = False) -> None:
        """Start the background daemon socket server."""
        class _CustomTCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        self._server = _CustomTCPServer((self.host, self.port), _DaemonTCPHandler)
        self._server.daemon_instance = self  # type: ignore

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop and shutdown the daemon service."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
