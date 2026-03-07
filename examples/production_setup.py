import json
from pathlib import Path
from guardclaw.core.modes import init_strict_mode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.genesis import GenesisRecord, AgentRegistration
from guardclaw.core.observers import Observer


def main():
    print("=" * 60)
    print("GuardClaw: Production Setup")
    print("=" * 60)

    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    ledger_dir = Path("ledger")
    ledger_dir.mkdir(exist_ok=True)

    print("[1] Generating root key...")
    root_key = Ed25519KeyManager.generate()
    root_key.save(keys_dir / "root.key")
    print("    Root key: " + root_key.public_key_hex[:16] + "...")

    print("[2] Creating genesis record...")
    genesis = GenesisRecord.create(
        ledger_name="Production Ledger",
        created_by="admin@example.com",
        root_key_manager=root_key,
        purpose="AI Agent Authorization - Production",
        jurisdiction="US-CA",
        metadata={"environment": "production", "version": "1.0.0"},
    )
    (ledger_dir / "genesis.json").write_text(json.dumps(genesis.to_dict(), indent=2))
    print("    Genesis ID: " + genesis.genesis_id[:16] + "...")

    print("[3] Generating agent key...")
    agent_key = Ed25519KeyManager.generate()
    agent_key.save(keys_dir / "agent-001.key")
    print("    Agent key: " + agent_key.public_key_hex[:16] + "...")

    print("[4] Registering agent...")
    agent_reg = AgentRegistration.create(
        agent_id="agent-001",
        agent_name="Production Agent",
        registered_by="admin@example.com",
        delegating_key_manager=root_key,
        agent_key_manager=agent_key,
        capabilities=["file:read", "file:write", "file:delete"],
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2027-01-01T00:00:00.000Z",
    )
    agents_dir = ledger_dir / "agents"
    agents_dir.mkdir(exist_ok=True)
    (agents_dir / "agent-001.json").write_text(json.dumps(agent_reg.to_dict(), indent=2))
    print("    Agent: " + agent_reg.agent_id)

    print("[5] Initializing Strict Mode...")
    mode_manager = init_strict_mode()
    mode_manager.set_signing_key(agent_key)
    mode_manager.validate_genesis(genesis)
    mode_manager.validate_agent_registration(agent_reg)
    print("    Genesis and agent validated")

    print("[6] Emitting to production ledger...")
    ledger_path = ledger_dir / "production.jsonl"
    ledger = mode_manager.create_ledger(
        ledger_path=ledger_path,
        signer_id="agent-001"
    )
    obs = Observer(agent_id="agent-001", ledger=ledger)
    obs.on_intent("Delete old log files")
    obs.on_execution("file:delete")
    obs.on_result("file:delete", {"files_deleted": 127})
    print("    3 entries emitted")

    print("" + "=" * 60)
    print("Production setup complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
