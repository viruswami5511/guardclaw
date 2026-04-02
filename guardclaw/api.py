"""
guardclaw/api.py

Public API surface for GuardClaw.
Primary entry points: session (= GEFSession), record_action(), verify_ledger().

CHANGE LOG:
    v0.2.3 — GEFSession context manager added (Phase 2A).
             trigger_hash: SHA-256 of raw trigger — raw text never persisted (Phase 2B).
             session_id: uuid4 per session, injected into every payload.
             action_id: uuid4 per action, injected into every payload.
             input/output/metadata normalization via json.loads(json.dumps(..., default=str))
             guarantees deterministic signing regardless of input type.
             session = GEFSession alias replaces @contextmanager wrapper.

    v0.5.0 — Phase 5: GEFSession.__exit__ now prints artifact path for visibility.
             _display_path() helper added.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardclaw.core.emitter import get_global_ledger
from guardclaw.core.models import ExecutionEnvelope, RecordType
from guardclaw.core.time import gef_timestamp


# ── Path display helper ───────────────────────────────────────

def _display_path(p: str) -> str:
    """Return path relative to cwd for readability. Falls back to absolute."""
    try:
        return str(Path(p).relative_to(Path.cwd()))
    except Exception:
        return p


# ─────────────────────────────────────────────────────────────
# GEFSession — context manager API
# ─────────────────────────────────────────────────────────────

class GEFSession:
    """
    Context manager for recording a bounded agent execution session.

    Usage:
        import guardclaw

        with guardclaw.session(agent_id="researcher-v1") as s:
            result = search_tool(query="climate change")
            s.record(
                action="web_search",
                input={"query": "climate change"},
                output=result,
                trigger="user_prompt_abc123",
            )

    Every record() call produces a signed, chain-hashed ExecutionEnvelope.
    session_id and action_id are injected automatically into every payload.
    input/output/metadata are normalized to JSON-safe structures before signing,
    guaranteeing deterministic hashes regardless of input type.
    trigger is stored only as SHA-256 — raw text is never persisted.

    On __exit__, prints the ledger path for artifact visibility.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.session_id = str(uuid.uuid4())
        self._ledger = get_global_ledger()
        self._entries: List[ExecutionEnvelope] = []

    def record(
        self,
        action: str,
        input: Optional[Dict[str, Any]] = None,
        output: Any = None,
        trigger: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExecutionEnvelope:
        """Record a single signed agent action within this session."""

        raw_input = input if input is not None else None
        try:
            safe_input = json.loads(json.dumps(raw_input, default=str))
        except Exception:
            safe_input = str(raw_input)

        try:
            safe_output = json.loads(json.dumps(output, default=str))
        except Exception:
            safe_output = str(output)

        try:
            safe_metadata = json.loads(json.dumps(metadata or {}, default=str))
        except Exception:
            safe_metadata = str(metadata)

        payload: Dict[str, Any] = {
            "agent_id":   self.agent_id,
            "session_id": self.session_id,
            "action_id":  str(uuid.uuid4()),
            "action":     action,
            "input":      safe_input,
            "output":     safe_output,
            "metadata":   safe_metadata,
            "timestamp":  gef_timestamp(),
        }

        if trigger is not None:
            payload["trigger_hash"] = hashlib.sha256(
                trigger.encode("utf-8")
            ).hexdigest()

        env = self._ledger.emit(
            record_type=RecordType.EXECUTION,
            payload=payload,
        )

        self._entries.append(env)
        return env

    def entries(self) -> List[ExecutionEnvelope]:
        return list(self._entries)

    def __enter__(self) -> "GEFSession":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._entries and self._ledger is not None:
            try:
                dp = _display_path(self._ledger.get_path())
                print(f"\n[guardclaw] Ledger written: {dp}")
                print(f"  Verify:   guardclaw verify {dp}")
                print(f"  Export:   guardclaw export {dp}\n")
            except Exception:
                pass
        return None


# Ergonomic alias — primary public API
session = GEFSession


# ─────────────────────────────────────────────────────────────
# Legacy / adapter entry points
# ─────────────────────────────────────────────────────────────

def get_ledger():
    return get_global_ledger()


def record_action(
    agent_id: str,
    action: str,
    result: str,
    metadata: Optional[Dict[str, Any]] = None,
    trigger: Optional[str] = None,
) -> ExecutionEnvelope:
    """Record a signed agent action directly (no context manager)."""

    ledger = get_global_ledger()

    try:
        safe_result = json.loads(json.dumps(result, default=str))
    except Exception:
        safe_result = str(result)

    try:
        safe_metadata = json.loads(json.dumps(metadata or {}, default=str))
    except Exception:
        safe_metadata = str(metadata)

    payload: Dict[str, Any] = {
        "agent_id":  agent_id,
        "action_id": str(uuid.uuid4()),
        "action":    action,
        "result":    safe_result,
        "metadata":  safe_metadata,
        "timestamp": gef_timestamp(),
    }

    if trigger is not None:
        payload["trigger_hash"] = hashlib.sha256(
            trigger.encode("utf-8")
        ).hexdigest()

    return ledger.emit(
        record_type=RecordType.EXECUTION,
        payload=payload,
    )


def verify_ledger(ledger_path: str):
    from guardclaw.verification.verify import verify_ledger_file
    return verify_ledger_file(ledger_path)