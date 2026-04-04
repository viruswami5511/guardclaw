"""
guardclaw/core/ledger.py

GEFLedger — the core truth store for GuardClaw.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import List, Optional

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import (
    ExecutionEnvelope,
    _VALID_RECORD_TYPES,
)


class GEFLedger:
    LEDGERFILENAME = "ledger.jsonl"
    LEDGER_FILENAME = "ledger.jsonl"

    def __init__(
        self,
        key_manager: Ed25519KeyManager,
        agent_id: str,
        ledgerpath: Optional[str] = None,
        ledgerdir: Optional[str] = None,
        ledger_path: Optional[str] = None,
        mode: str = "strict",
        ledger_filename: Optional[str] = None,
    ) -> None:

        if mode not in ("strict", "ghost"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'strict' or 'ghost'.")

        resolved = ledgerpath or ledger_path or ledgerdir

        if mode == "strict" and resolved is None:
            raise ValueError("ledger_path is required for strict mode.")

        self._key_manager = key_manager
        self._agent_id = agent_id
        self._mode = mode
        self._chain: List[ExecutionEnvelope] = []
        self._lock = threading.Lock()

        if mode == "ghost":
            self._ledger_file: Optional[Path] = None
        else:
            lp = Path(resolved)
            lp.mkdir(parents=True, exist_ok=True)

            fname = ledger_filename or self.LEDGERFILENAME
            self._ledger_file = lp / fname

            self._recover_file()
            self._load_existing_chain()

    # ── Public API ────────────────────────────────────────────

    def get_path(self) -> str:
        return str(self._ledger_file)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def public_key_hex(self) -> str:
        return self._key_manager.public_key_hex

    @property
    def entries(self) -> List[ExecutionEnvelope]:
        return list(self._chain)

    def entry_count(self) -> int:
        return len(self._chain)

    def head(self) -> Optional[ExecutionEnvelope]:
        return self._chain[-1] if self._chain else None

    # ── Core: emit ────────────────────────────────────────────

    def emit(
        self,
        record_type: str,
        payload: dict,
    ) -> ExecutionEnvelope:

        if record_type not in _VALID_RECORD_TYPES:
            raise ValueError(
                f"Invalid record_type '{record_type}'. "
                f"Valid: {sorted(_VALID_RECORD_TYPES)}"
            )

        with self._lock:
            prev = self._chain[-1] if self._chain else None

            env = ExecutionEnvelope.create(
                record_type=record_type,
                agent_id=self._agent_id,
                signer_public_key=self._key_manager.public_key_hex,
                sequence=len(self._chain),
                payload=payload,
                prev=prev,
            ).sign(self._key_manager)

            self._chain.append(env)
            self._persist(env)

            return env

    # ── Persistence ───────────────────────────────────────────

    def _persist(self, env: ExecutionEnvelope) -> None:
        if self._ledger_file is None:
            return

        with open(self._ledger_file, "a", encoding="utf-8", newline="") as f:
            f.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
            f.flush()

    # ── Crash Recovery ────────────────────────────────────────

    def _recover_file(self) -> None:
        """Strip incomplete last line only (true crash recovery)."""
        if self._ledger_file is None or not self._ledger_file.exists():
            return

        with open(self._ledger_file, "rb") as f:
            content = f.read()

        if not content:
            return

        if not content.endswith(b"\n"):
            last_newline = content.rfind(b"\n")

            if last_newline != -1:
                content = content[: last_newline + 1]
            else:
                content = b""

            with open(self._ledger_file, "wb") as f:
                f.write(content)

    # ── State Restore ─────────────────────────────────────────

    def _load_existing_chain(self) -> None:
        """Load existing valid entries into memory for sequence + hash continuity."""
        if self._ledger_file is None or not self._ledger_file.exists():
            return

        self._chain = []

        with open(self._ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue

                try:
                    data = json.loads(raw)
                    env = ExecutionEnvelope.from_dict(data)
                except Exception:
                    break

                self._chain.append(env)

    def close(self) -> None:
        return None

    # ── Verification ──────────────────────────────────────────

    def verify_chain(self) -> bool:
        if self._ledger_file is None:
            return True

        from guardclaw.core.replay import ReplayEngine

        engine = ReplayEngine(parallel=False, silent=True)
        engine.load(str(self._ledger_file))
        summary = engine.verify()

        # FIX: was summary.chain_valid — correct attribute is summary.chainvalid
        return summary.chainvalid

    # ── Class method: load ────────────────────────────────────

    @classmethod
    def load(
        cls,
        ledger_path: str,
        key_manager: Ed25519KeyManager,
        agent_id: str = "loaded",
    ) -> "GEFLedger":

        path = Path(ledger_path)

        if not path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")

        instance = cls.__new__(cls)

        instance._key_manager = key_manager
        instance._agent_id = agent_id
        instance._mode = "strict"
        instance._chain = []
        instance._lock = threading.Lock()
        instance._ledger_file = path

        instance._recover_file()
        instance._load_existing_chain()

        return instance

    def __repr__(self) -> str:
        return (
            f"GEFLedger("
            f"agent_id={self._agent_id!r}, "
            f"entries={len(self._chain)}, "
            f"path={self.get_path()!r}"
            f")"
        )