"""
GuardClaw: Production Setup Example

Demonstrates:
- Strict mode setup
- Explicit genesis creation
- Agent registration
- Production-grade evidence emission
"""

import json
from pathlib import Path
from guardclaw.core.modes import init_strict_mode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.genesis import GenesisRecord, AgentRegistration
from guardclaw.core.emitter import init_global_emitter
from guardclaw.adapters import GenericAgentObserver


def setup_production():
    """Setup production GuardClaw environment."""
    
    print("="*60)
    print("GuardClaw: Production Setup")
    print("="*60)
    print()
    
    # Create directories
    keys_dir = Path("keys")
    ledger_dir = Path("ledger")
    keys_dir.mkdir(exist_ok=True)
    ledger_dir.mkdir(exist_ok=True)
    
    # 1️⃣ Generate root key
    print("1️⃣ Generating root key...")
    root_key = Ed25519KeyManager.generate()
    root_key.save_keypair(
        private_key_path=keys_dir / "root.key",
        public_key_path=keys_dir / "root.pub"
    )
    print(f"  ✅ Root key: {root_key.public_key_hex()[:16]}...")
    print(f"  ✅ Saved: keys/root.key")
    print()
    
    # 2️⃣ Create genesis
    print("2️⃣ Creating genesis record...")
    genesis = GenesisRecord.create(
        ledger_name="Production Ledger",
        created_by="admin@example.com",
        root_key_manager=root_key,
        purpose="AI Agent Authorization - Production",
        jurisdiction="US-CA",
        metadata={
            "environment": "production",
            "version": "1.0.0"
        }
    )
    
    # Save genesis
    genesis_file = ledger_dir / "genesis.json"
    with open(genesis_file, 'w') as f:
        json.dump(genesis.to_dict(), f, indent=2)
    
    print(f"  ✅ Genesis ID: {genesis.genesis_id[:16]}...")
    print(f"  ✅ Saved: ledger/genesis.json")
    print()
    
    # 3️⃣ Generate agent key
    print("3️⃣ Generating agent key...")
    agent_key = Ed25519KeyManager.generate()
    agent_key.save_keypair(
        private_key_path=keys_dir / "agent-001.key",
        public_key_path=keys_dir / "agent-001.pub"
    )
    print(f"  ✅ Agent key: {agent_key.public_key_hex()[:16]}...")
    print(f"  ✅ Saved: keys/agent-001.key")
    print()
    
    # 4️⃣ Register agent
    print("4️⃣ Registering agent...")
    agent_reg = AgentRegistration.create(
        agent_id="agent-001",
        agent_name="Production Agent",
        registered_by="admin@example.com",
        delegating_key_manager=root_key,
        agent_key_manager=agent_key,
        capabilities=["file:read", "file:write", "file:delete"],
        valid_from="2026-02-10T00:00:00Z",
        valid_until="2027-02-10T00:00:00Z"
    )
    
    # Save agent registration
    agents_dir = ledger_dir / "agents"
    agents_dir.mkdir(exist_ok=True)
    agent_file = agents_dir / "agent-001.json"
    with open(agent_file, 'w') as f:
        json.dump(agent_reg.to_dict(), f, indent=2)
    
    print(f"  ✅ Agent ID: {agent_reg.agent_id}")
    print(f"  ✅ Capabilities: {', '.join(agent_reg.capabilities)}")
    print(f"  ✅ Valid until: {agent_reg.valid_until}")
    print(f"  ✅ Saved: ledger/agents/agent-001.json")
    print()
    
    # 5️⃣ Initialize Strict Mode
    print("5️⃣ Initializing Strict Mode...")
    mode_manager = init_strict_mode()
    
    # Validate setup
    mode_manager.validate_genesis(genesis)
    mode_manager.validate_agent_registration(agent_reg)
    
    print("  ✅ Genesis validated")
    print("  ✅ Agent registration validated")
    print()
    
    # 6️⃣ Start evidence emitter
    print("6️⃣ Starting evidence emitter...")
    emitter = init_global_emitter(
        key_manager=agent_key,
        buffer_dir=Path(".guardclaw/buffer"),
        signing_interval_seconds=1.0
    )
    print("  ✅ Evidence emitter started")
    print()
    
    print("="*60)
    print("✅ Production setup complete!")
    print("="*60)
    print()
    print("Your production environment is ready:")
    print("  - Mode: STRICT (production-grade)")
    print("  - Genesis: ledger/genesis.json")
    print("  - Agent: agent-001 (file operations)")
    print("  - Keys: keys/ (secure these!)")
    print()
    print("Next steps:")
    print("  1. Backup keys/ directory (CRITICAL)")
    print("  2. Secure root key (HSM recommended)")
    print("  3. Deploy agent with agent-001 key")
    print("  4. Monitor evidence: .guardclaw/ledger/observations/")
    
    return mode_manager, emitter, agent_key


def demo_production_usage(emitter, agent_key):
    """Demonstrate production usage."""
    
    print()
    print("="*60)
    print("Production Usage Demo")
    print("="*60)
    print()
    
    # Create agent observer
    agent_obs = GenericAgentObserver(agent_id="agent-001")
    
    # Simulate production workflow
    print("1️⃣ User request: Delete old log files")
    agent_obs.observe_intent("Delete old log files")
    
    print("2️⃣ Agent executes: file:delete")
    agent_obs.observe_action("file:delete")
    
    print("3️⃣ Result: 127 files deleted")
    agent_obs.observe_result({"files_deleted": 127, "bytes_freed": 4500000000})
    
    print("4️⃣ Stopping agent...")
    agent_obs.stop()
    
    print()
    print("✅ Production workflow complete")
    print("  Evidence signed and stored in ledger")
    print("  Ready for audit or review")


if __name__ == "__main__":
    # Setup
    mode_manager, emitter, agent_key = setup_production()
    
    # Demo usage
    demo_production_usage(emitter, agent_key)
    
    # Cleanup
    print()
    print("Stopping emitter...")
    emitter.stop(timeout=5.0)
    print("✅ Done")
