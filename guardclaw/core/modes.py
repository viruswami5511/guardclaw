"""
GuardClaw Phase 5: Ghost vs Strict Modes

Ghost Mode: Zero-ceremony development (ephemeral keys)
Strict Mode: Production-grade enforcement (persistent keys)
"""

import os
import warnings
from enum import Enum
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.genesis import GenesisRecord, AgentRegistration


class GuardClawMode(Enum):
    """GuardClaw operational modes."""
    GHOST = "ghost"
    STRICT = "strict"


class GuardClawModeError(Exception):
    """Raised when mode validation fails in Strict mode."""
    pass


@dataclass
class ModeConfig:
    """Configuration for GuardClaw mode."""
    mode: GuardClawMode
    require_genesis: bool
    require_agent_registration: bool
    enforce_delegation: bool
    enforce_expiry: bool
    warn_on_violation: bool
    fail_on_violation: bool
    use_ephemeral_keys: bool


class ModeManager:
    """
    Manages GuardClaw operational mode (Ghost or Strict).
    
    Ghost Mode:
    - Zero ceremony setup
    - Ephemeral keys (saved to .guardclaw/keys/ for replay verification)
    - Auto-generated genesis + agent
    - Warnings only, no failures
    
    Strict Mode:
    - Explicit genesis required
    - Explicit agent registration required
    - Delegation enforcement
    - Hard failures on violations
    """
    
    def __init__(self, config: ModeConfig):
        self.config = config
        
        # Ephemeral resources (Ghost mode only)
        self._ephemeral_root_key: Optional[Ed25519KeyManager] = None
        self._ephemeral_agent_key: Optional[Ed25519KeyManager] = None
        self._ephemeral_genesis: Optional[GenesisRecord] = None
        self._ephemeral_agent_registration: Optional[AgentRegistration] = None
        
        # Print mode banner
        self._print_banner()
    
    def _print_banner(self) -> None:
        """Print mode banner on initialization."""
        if self.config.mode == GuardClawMode.GHOST:
            print("="*60)
            print("⚠️  GUARDCLAW GHOST MODE ACTIVE")
            print("="*60)
            print("• Genesis: AUTO-GENERATED (ephemeral)")
            print("• Agent: AUTO-REGISTERED (no delegation chain)")
            print("• Evidence: CRYPTOGRAPHICALLY VALID")
            print("• Violations: WARNINGS ONLY")
            print()
            print("This mode is for DEVELOPMENT ONLY.")
            print("For production, use STRICT MODE:")
            print("  export GUARDCLAW_MODE=strict")
            print("="*60)
        else:
            print("="*60)
            print("✅ GUARDCLAW STRICT MODE ACTIVE")
            print("="*60)
            print("• Genesis: REQUIRED (must be explicit)")
            print("• Agent: REQUIRED (must be registered)")
            print("• Delegation: ENFORCED")
            print("• Violations: HARD FAILURES")
            print()
            print("Production-grade accountability enabled.")
            print("="*60)
    
    def validate_genesis(self, genesis: Optional[GenesisRecord]) -> None:
        """
        Validate genesis record.
        
        Ghost mode: Warning only
        Strict mode: Raises if missing
        """
        if not self.config.require_genesis:
            return
        
        if genesis is None:
            msg = "Genesis record required in Strict mode"
            if self.config.fail_on_violation:
                raise GuardClawModeError(msg)
            if self.config.warn_on_violation:
                warnings.warn(msg)
    
    def validate_agent_registration(self, agent_reg: Optional[AgentRegistration]) -> None:
        """
        Validate agent registration.
        
        Ghost mode: Warning only
        Strict mode: Raises if missing
        """
        if not self.config.require_agent_registration:
            return
        
        if agent_reg is None:
            msg = "Agent registration required in Strict mode"
            if self.config.fail_on_violation:
                raise GuardClawModeError(msg)
            if self.config.warn_on_violation:
                warnings.warn(msg)
    
    def validate_delegation_chain(self, delegations: list, required: bool = False) -> None:
        """
        Validate delegation chain.
        
        Ghost mode: Ignored
        Strict mode: Enforced if required=True
        """
        if not self.config.enforce_delegation:
            return
        
        if required and not delegations:
            msg = "Delegation chain required in Strict mode"
            if self.config.fail_on_violation:
                raise GuardClawModeError(msg)
            if self.config.warn_on_violation:
                warnings.warn(msg)
    
    def validate_expiry(self, valid_from: str, valid_until: str, current_time: str) -> None:
        """
        Validate time-based expiry.
        
        Ghost mode: Ignored
        Strict mode: Enforced
        """
        if not self.config.enforce_expiry:
            return
        
        from datetime import datetime, timezone
        
        valid_from_dt = datetime.fromisoformat(valid_from.replace('Z', '+00:00'))
        valid_until_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
        current_dt = datetime.fromisoformat(current_time.replace('Z', '+00:00'))
        
        if current_dt < valid_from_dt:
            msg = f"Not yet valid (valid from {valid_from})"
            if self.config.fail_on_violation:
                raise GuardClawModeError(msg)
            if self.config.warn_on_violation:
                warnings.warn(msg)
        
        if current_dt > valid_until_dt:
            msg = f"Expired (valid until {valid_until})"
            if self.config.fail_on_violation:
                raise GuardClawModeError(msg)
            if self.config.warn_on_violation:
                warnings.warn(msg)
    
    def get_ephemeral_root_key(self) -> Ed25519KeyManager:
        """Get or create ephemeral root key (Ghost mode only)."""
        if self._ephemeral_root_key is None:
            self._ephemeral_root_key = Ed25519KeyManager.generate()
            
            # SAVE to disk for replay verification
            key_dir = Path(".guardclaw/keys")
            key_dir.mkdir(parents=True, exist_ok=True)
            
            self._ephemeral_root_key.save_keypair(
                private_key_path=key_dir / "ephemeral_root.key",
                public_key_path=key_dir / "ephemeral_root.pub"
            )
        
        return self._ephemeral_root_key
    
    def get_ephemeral_agent_key(self) -> Ed25519KeyManager:
        """Get or create ephemeral agent key (Ghost mode only)."""
        if self._ephemeral_agent_key is None:
            self._ephemeral_agent_key = Ed25519KeyManager.generate()
            
            # SAVE to disk for replay verification
            key_dir = Path(".guardclaw/keys")
            key_dir.mkdir(parents=True, exist_ok=True)
            
            self._ephemeral_agent_key.save_keypair(
                private_key_path=key_dir / "ephemeral_agent.key",
                public_key_path=key_dir / "ephemeral_agent.pub"
            )
        
        return self._ephemeral_agent_key
    
    def get_ephemeral_genesis(self) -> GenesisRecord:
        """Get or create ephemeral genesis (Ghost mode only)."""
        if self._ephemeral_genesis is None:
            from datetime import datetime, timezone
            import json
            
            root_key = self.get_ephemeral_root_key()
            
            self._ephemeral_genesis = GenesisRecord.create(
                ledger_name="Ephemeral Development Ledger",
                created_by="ghost-mode@guardclaw.dev",
                root_key_manager=root_key,
                purpose="Development and testing",
                metadata={
                    "mode": "ghost",
                    "ephemeral": True,
                    "warning": "Not for production use"
                }
            )
            
            # SAVE to disk for replay
            genesis_dir = Path(".guardclaw/ledger")
            genesis_dir.mkdir(parents=True, exist_ok=True)
            
            genesis_file = genesis_dir / "genesis.json"
            with open(genesis_file, 'w') as f:
                json.dump(self._ephemeral_genesis.to_dict(), f, indent=2)
        
        return self._ephemeral_genesis
    
    def get_ephemeral_agent_registration(self) -> AgentRegistration:
        """Get or create ephemeral agent registration (Ghost mode only)."""
        if self._ephemeral_agent_registration is None:
            from datetime import datetime, timezone, timedelta
            import json
            
            root_key = self.get_ephemeral_root_key()
            agent_key = self.get_ephemeral_agent_key()
            
            now = datetime.now(timezone.utc)
            valid_from = now.isoformat()
            valid_until = (now + timedelta(days=365)).isoformat()
            
            self._ephemeral_agent_registration = AgentRegistration.create(
                agent_id="ghost-agent",
                agent_name="Ephemeral Ghost Agent",
                registered_by="ghost-mode@guardclaw.dev",
                delegating_key_manager=root_key,
                agent_key_manager=agent_key,
                capabilities=["*"],  # All capabilities
                valid_from=valid_from,
                valid_until=valid_until,
                metadata={
                    "mode": "ghost",
                    "ephemeral": True
                }
            )
            
            # SAVE to disk for replay
            agents_dir = Path(".guardclaw/agents")
            agents_dir.mkdir(parents=True, exist_ok=True)
            
            agent_file = agents_dir / "ghost-agent.json"
            with open(agent_file, 'w') as f:
                json.dump(self._ephemeral_agent_registration.to_dict(), f, indent=2)
        
        return self._ephemeral_agent_registration


def init_ghost_mode() -> ModeManager:
    """
    Initialize Ghost mode (development).
    
    Ghost mode:
    - Zero ceremony
    - Ephemeral keys (saved to .guardclaw/keys/ for replay)
    - Auto-generated genesis + agent
    - Warnings only, no failures
    
    Returns:
        ModeManager configured for Ghost mode
    """
    config = ModeConfig(
        mode=GuardClawMode.GHOST,
        require_genesis=False,
        require_agent_registration=False,
        enforce_delegation=False,
        enforce_expiry=False,
        warn_on_violation=True,
        fail_on_violation=False,
        use_ephemeral_keys=True
    )
    
    manager = ModeManager(config)
    
    # Pre-generate ephemeral resources (so they're saved to disk)
    manager.get_ephemeral_genesis()
    manager.get_ephemeral_agent_registration()
    
    return manager


def init_strict_mode() -> ModeManager:
    """
    Initialize Strict mode (production).
    
    Strict mode:
    - Explicit genesis required
    - Explicit agent registration required
    - Delegation enforced
    - Expiry enforced
    - Hard failures on violations
    
    Returns:
        ModeManager configured for Strict mode
    """
    config = ModeConfig(
        mode=GuardClawMode.STRICT,
        require_genesis=True,
        require_agent_registration=True,
        enforce_delegation=True,
        enforce_expiry=True,
        warn_on_violation=True,
        fail_on_violation=True,
        use_ephemeral_keys=False
    )
    
    return ModeManager(config)


def init_mode_from_env() -> ModeManager:
    """
    Initialize mode from environment variable.
    
    Reads GUARDCLAW_MODE environment variable:
    - "ghost" → Ghost mode
    - "strict" → Strict mode
    - Not set → Ghost mode (default)
    
    Returns:
        ModeManager
    """
    mode_str = os.environ.get("GUARDCLAW_MODE", "ghost").lower()
    
    if mode_str == "strict":
        return init_strict_mode()
    else:
        return init_ghost_mode()
