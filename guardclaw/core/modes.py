"""
GuardClaw GEF: Ghost and Strict Modes.
"""

import os
import warnings
import json
from enum import Enum
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.genesis import GenesisRecord, AgentRegistration
from guardclaw.core.models import RecordType


class GuardClawMode(Enum):
    GHOST = "ghost"
    STRICT = "strict"


class GuardClawModeError(Exception):
    pass


@dataclass
class ModeConfig:
    mode: GuardClawMode
    require_genesis: bool
    require_agent_registration: bool
    enforce_delegation: bool
    enforce_expiry: bool
    warn_on_violation: bool
    fail_on_violation: bool
    use_ephemeral_keys: bool


class ModeManager:

    def __init__(self, config: ModeConfig):
        self.config = config
        self._root_key = None
        self._agent_key = None
        self._genesis = None
        self._agent_reg = None
        self._print_banner()

    def create_ledger(self, ledger_path: Path, signer_id: str = "default"):
        from guardclaw.core.emitter import GEFLedger
        if self.config.use_ephemeral_keys:
            key = self._get_or_create_root_key()
            self._ensure_genesis_emitted(ledger_path, signer_id, key)
        else:
            if self._root_key is None:
                raise GuardClawModeError(
                    "Strict mode requires an explicit signing key. "
                    "Call set_signing_key() before create_ledger()."
                )
            key = self._root_key
        return GEFLedger(
    key_manager=key,
    agent_id=signer_id,
    ledger_path=str(ledger_path),
)

    def set_signing_key(self, key: Ed25519KeyManager) -> None:
        self._root_key = key

    def validate_genesis(self, genesis) -> None:
        if not self.config.require_genesis:
            return
        if genesis is None:
            self._violation("Genesis record required in Strict mode")

    def validate_agent_registration(self, reg) -> None:
        if not self.config.require_agent_registration:
            return
        if reg is None:
            self._violation("Agent registration required in Strict mode")

    def validate_delegation_chain(self, delegations: list, required: bool = False) -> None:
        if not self.config.enforce_delegation:
            return
        if required and not delegations:
            self._violation("Delegation chain required in Strict mode")

    def validate_expiry(self, valid_from: str, valid_until: str, current_time: str) -> None:
        if not self.config.enforce_expiry:
            return
        from datetime import datetime, timezone
        vf = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        vu = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        now = datetime.fromisoformat(current_time.replace("Z", "+00:00"))
        if now < vf:
            self._violation(f"Not yet valid (valid_from={valid_from})")
        if now > vu:
            self._violation(f"Expired (valid_until={valid_until})")

    def _violation(self, msg: str) -> None:
        if self.config.fail_on_violation:
            raise GuardClawModeError(msg)
        if self.config.warn_on_violation:
            warnings.warn(msg)

    def _get_or_create_root_key(self) -> Ed25519KeyManager:
        if self._root_key is None:
            key_dir = Path(".guardclaw/keys")
            key_dir.mkdir(parents=True, exist_ok=True)
            priv = key_dir / "ephemeral_root.key"
            if priv.exists():
                self._root_key = Ed25519KeyManager.from_file(priv)
            else:
                self._root_key = Ed25519KeyManager.generate()
                self._root_key.save(priv)
        return self._root_key

    def _ensure_genesis_emitted(self, ledger_path: Path, signer_id: str, key: Ed25519KeyManager) -> None:
        if ledger_path.exists() and ledger_path.stat().st_size > 0:
            return
        if self._genesis is None:
            self._genesis = GenesisRecord.create(
                ledger_name="Ephemeral Development Ledger",
                created_by=f"{signer_id}@ghost.guardclaw",
                root_key_manager=key,
                purpose="Development and testing",
                metadata={"mode": "ghost", "ephemeral": True},
            )
            genesis_dir = Path(".guardclaw/ledger")
            genesis_dir.mkdir(parents=True, exist_ok=True)
            with open(genesis_dir / "genesis.json", "w") as f:
                json.dump(self._genesis.to_dict(), f, indent=2)
        from guardclaw.core.emitter import GEFLedger
        tmp_ledger = GEFLedger(key_manager=key, agent_id=signer_id, ledger_path=str(ledger_path))
        tmp_ledger.emit(RecordType.GENESIS, self._genesis.to_dict())

    def _print_banner(self) -> None:
        if self.config.mode == GuardClawMode.GHOST:
            print("GuardClaw GHOST MODE - development only. Keys are ephemeral.")
        else:
            print("GuardClaw STRICT MODE - production enforcement active.")


def init_ghost_mode() -> ModeManager:
    return ModeManager(ModeConfig(
        mode=GuardClawMode.GHOST,
        require_genesis=False,
        require_agent_registration=False,
        enforce_delegation=False,
        enforce_expiry=False,
        warn_on_violation=True,
        fail_on_violation=False,
        use_ephemeral_keys=True,
    ))


def init_strict_mode() -> ModeManager:
    return ModeManager(ModeConfig(
        mode=GuardClawMode.STRICT,
        require_genesis=True,
        require_agent_registration=True,
        enforce_delegation=True,
        enforce_expiry=True,
        warn_on_violation=True,
        fail_on_violation=True,
        use_ephemeral_keys=False,
    ))


def init_mode_from_env() -> ModeManager:
    return init_strict_mode() \
        if os.environ.get("GUARDCLAW_MODE", "ghost").lower() == "strict" \
        else init_ghost_mode()
