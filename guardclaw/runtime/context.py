"""
Runtime context for GuardClaw execution.
Updated to use current GEF API only.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.emitter import GEFLedger


@dataclass
class RuntimeContext:
    """Runtime context for GuardClaw-protected execution."""
    ledger: GEFLedger
    key_manager: Ed25519KeyManager
    executor_id: str

    @classmethod
    def from_config(
        cls,
        ledger_path: Path,
        executor_id: str = "default-executor",
        key_manager: Optional[Ed25519KeyManager] = None,
    ) -> "RuntimeContext":
        km = key_manager or Ed25519KeyManager.generate()
        ledger = GEFLedger(
            ledger_path=ledger_path,
            signing_key=km,
            signer_id=executor_id,
        )
        return cls(
            ledger=ledger,
            key_manager=km,
            executor_id=executor_id,
        )

    def __repr__(self) -> str:
        return f"RuntimeContext(executor_id={self.executor_id!r})"