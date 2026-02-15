"""
Runtime context for GuardClaw execution.
"""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path

from guardclaw.core.crypto import KeyManager
from guardclaw.compat import PolicyEngine, SettlementEngine, Ledger


@dataclass
class RuntimeContext:
    """Runtime context for GuardClaw-protected execution."""
    
    policy_engine: PolicyEngine
    settlement_engine: SettlementEngine
    ledger: Ledger
    key_manager: KeyManager
    executor_id: str
    
    @classmethod
    def from_config(
        cls,
        policy_file: Path,
        ledger_path: Path,
        key_path: Optional[Path] = None,
        executor_id: str = "default-executor"
    ) -> "RuntimeContext":
        """Create runtime context from configuration files."""
        # Initialize key manager
        if key_path and key_path.exists():
            key_manager = KeyManager.load_key(key_path)
        else:
            key_manager = KeyManager.generate_key()
            if key_path:
                key_manager.save_key(key_path)
        
        # Initialize components
        policy_engine = PolicyEngine.from_yaml(policy_file, key_manager)
        ledger = Ledger.load_or_create(ledger_path, key_manager)
        settlement_engine = SettlementEngine(ledger, key_manager)
        
        return cls(
            policy_engine=policy_engine,
            settlement_engine=settlement_engine,
            ledger=ledger,
            key_manager=key_manager,
            executor_id=executor_id
        )
    
    def __repr__(self) -> str:
        return (
            f"RuntimeContext("
            f"executor_id={self.executor_id!r}, "
            f"ledger_entries={len(self.ledger.entries)})"
        )
