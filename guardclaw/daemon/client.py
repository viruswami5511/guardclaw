"""
guardclaw/daemon/client.py

Zero-Key Client for GuardClaw Signing Daemon.
Allows AI agents to record tamper-evident execution events with sub-millisecond
latency while possessing zero private keys or KMS credentials in process memory.
"""

from __future__ import annotations
import json
import socket
import uuid
from typing import Any, Dict, Optional

from guardclaw.core.models import ExecutionEnvelope, RecordType


class DaemonClient:
    """
    Zero-key RPC client connecting to an isolated GuardClaw signing daemon.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9443,
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def _get_connection(self) -> socket.socket:
        if self._sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            self._sock = s
        return self._sock

    def _rpc_call(self, method: str, params: Dict[str, Any]) -> Any:
        req_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
        msg = (json.dumps(payload) + "\n").encode("utf-8")

        for attempt in range(2):
            try:
                conn = self._get_connection()
                conn.sendall(msg)
                resp_bytes = b""
                while not resp_bytes.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        raise ConnectionResetError("Daemon closed connection")
                    resp_bytes += chunk
                break
            except (socket.error, ConnectionError):
                if self._sock:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    self._sock = None
                if attempt == 1:
                    raise

        resp = json.loads(resp_bytes.decode("utf-8").strip())
        if "error" in resp:
            raise RuntimeError(f"Daemon RPC Error: {resp['error']}")
        return resp.get("result")

    def ping(self) -> Dict[str, Any]:
        """Check daemon health and get signer public key."""
        return self._rpc_call("ping", {})

    def emit(
        self,
        record_type: str,
        payload: Dict[str, Any],
        key_id: Optional[str] = None,
    ) -> ExecutionEnvelope:
        """
        Emit an execution record to the daemon for out-of-process signing.
        """
        record_type = RecordType.normalize(record_type)
        res = self._rpc_call(
            "emit",
            {
                "record_type": record_type,
                "payload": payload,
                "key_id": key_id,
            },
        )
        return ExecutionEnvelope.from_dict(res)

    def get_head(self) -> Optional[ExecutionEnvelope]:
        res = self._rpc_call("get_head", {})
        return ExecutionEnvelope.from_dict(res) if res else None

    def get_merkle_root(self) -> str:
        res = self._rpc_call("get_root", {})
        return res.get("root_hash", "")

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> "DaemonClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
