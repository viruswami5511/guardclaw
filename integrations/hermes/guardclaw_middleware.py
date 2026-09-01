"""
integrations/hermes/guardclaw_middleware.py

GuardClaw Execution Audit Middleware for Nous Research Hermes Agent.
Hooks into the Hermes agent loop (before_agent / after_agent / tool lifecycle)
to record and cryptographically sign every tool execution in real-time.
"""

from __future__ import annotations
import os
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("hermes.middleware.guardclaw")

try:
    from guardclaw import GEFLedger, Ed25519KeyManager, RecordType, verify_ledger
    GUARDCLAW_AVAILABLE = True
except ImportError:
    GUARDCLAW_AVAILABLE = False


class GuardClawHermesMiddleware:
    """
    Hermes Agent middleware that cryptographically seals tool invocations
    using Ed25519 detached signatures and SHA-256 causal hash chaining (GEF-SPEC-1.0).
    """

    def __init__(self, audit_dir: Optional[str] = None, agent_id: str = "hermes-agent") -> None:
        self.audit_dir = audit_dir or os.environ.get("HERMES_AUDIT_DIR", "./hermes_audit_ledger")
        self.agent_id = agent_id
        self.ledger: Optional[Any] = None
        self._pending_intents: Dict[str, Any] = {}

        if GUARDCLAW_AVAILABLE:
            try:
                key_mgr = Ed25519KeyManager.generate()
                self.ledger = GEFLedger(
                    key_manager=key_mgr,
                    agent_id=self.agent_id,
                    ledger_path=self.audit_dir,
                )
                logger.info(f"GuardClaw audit middleware initialized for {self.agent_id} at {self.audit_dir}")
            except Exception as exc:
                logger.warning(f"Could not initialize GuardClaw ledger: {exc}")
        else:
            logger.debug("GuardClaw not installed; execution auditing disabled.")

    def on_tool_start(self, tool_name: str, tool_args: Dict[str, Any], call_id: Optional[str] = None) -> Optional[str]:
        """
        Called before Hermes executes a tool. Emits a TOOL_CALL intent envelope.
        """
        if not self.ledger:
            return None

        try:
            envelope = self.ledger.emit(
                record_type=RecordType.TOOL_CALL,
                payload={
                    "tool": tool_name,
                    "arguments": tool_args,
                    "call_id": call_id,
                },
            )
            key = call_id or tool_name
            self._pending_intents[key] = envelope.record_id
            return envelope.record_id
        except Exception as exc:
            logger.error(f"Failed to record tool start audit envelope: {exc}")
            return None

    def on_tool_end(self, tool_name: str, result: Any, call_id: Optional[str] = None, error: Optional[str] = None) -> Optional[str]:
        """
        Called after Hermes completes tool execution. Emits a TOOL_RESULT envelope.
        """
        if not self.ledger:
            return None

        key = call_id or tool_name
        intent_id = self._pending_intents.pop(key, None)

        try:
            status = "error" if error else "success"
            payload = {
                "tool": tool_name,
                "status": status,
                "call_id": call_id,
                "intent_record_id": intent_id,
            }
            if error:
                payload["error"] = str(error)
            else:
                payload["result_summary"] = str(result)[:500]

            envelope = self.ledger.emit(
                record_type=RecordType.TOOL_RESULT,
                payload=payload,
            )
            return envelope.record_id
        except Exception as exc:
            logger.error(f"Failed to record tool end audit envelope: {exc}")
            return None

    def verify(self) -> Dict[str, Any]:
        """Verify the integrity of the Hermes audit ledger."""
        if not GUARDCLAW_AVAILABLE:
            return {"chain_valid": False, "error": "guardclaw not installed"}
        return verify_ledger(self.audit_dir)
