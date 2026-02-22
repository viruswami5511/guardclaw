"""
GuardClaw: Basic Usage Example

Demonstrates:
- Ghost mode setup (zero ceremony)
- Agent observation
- Tool wrapping
- Evidence replay
"""

import time
from guardclaw.core.modes import init_ghost_mode
from guardclaw.core.emitter import init_global_emitter
from guardclaw.adapters import GenericAgentObserver, observe_tool
from guardclaw.core.replay import ReplayEngine


def main():
    """Basic GuardClaw usage."""
    
    print("="*60)
    print("GuardClaw: Basic Usage Example")
    print("="*60)
    print()
    
    # 1️⃣ Initialize Ghost Mode (zero ceremony)
    print("1️⃣ Initializing Ghost Mode...")
    mode_manager = init_ghost_mode()
    
    # Get ephemeral keys
    agent_key = mode_manager.get_ephemeral_agent_key()
    
    # Start evidence emitter
    emitter = init_global_emitter(
        key_manager=agent_key,
        signing_interval_seconds=1.0
    )
    
    print("✅ Ghost Mode active (ephemeral keys, zero setup)")
    print()
    
    # 2️⃣ Create agent observer
    print("2️⃣ Creating agent observer...")
    agent_obs = GenericAgentObserver(agent_id="demo-agent-001")
    print("✅ Agent observer ready")
    print()
    
    # 3️⃣ Simulate agent workflow
    print("3️⃣ Simulating agent workflow...")
    
    # User intent
    print("  📝 User: 'Calculate the sum of numbers 1 to 100'")
    agent_obs.observe_intent("Calculate the sum of numbers 1 to 100")
    
    # Agent executes
    print("  ⚡ Agent: Executing calculation...")
    agent_obs.observe_action("math:sum_range")
    
    # Define and execute a tool
    @observe_tool("math:sum_range", subject_id="demo-agent-001")
    def sum_range(start: int, end: int) -> int:
        """Calculate sum of range."""
        return sum(range(start, end + 1))
    
    result = sum_range(1, 100)
    print(f"  ✅ Result: {result}")
    
    # Agent reports result
    agent_obs.observe_result(result)
    
    # Stop observer
    agent_obs.stop()
    
    print("✅ Agent workflow complete")
    print()
    
    # 4️⃣ Wait for evidence signing
    print("4️⃣ Waiting for evidence signing...")
    time.sleep(2.0)
    
    # Show emitter stats
    stats = emitter.get_stats()
    print(f"  Events emitted: {stats['total_emitted']}")
    print(f"  Events signed: {stats['total_signed']}")
    print(f"  Events dropped: {stats['total_dropped']}")
    print("✅ Evidence signed and stored")
    print()
    
    # 5️⃣ Stop emitter
    print("5️⃣ Stopping emitter...")
    emitter.stop(timeout=5.0)
    print("✅ Emitter stopped gracefully")
    print()
    
    # 6️⃣ Replay evidence
    print("6️⃣ Replaying evidence...")
    print()
    
    # Note: In real usage, you would load from evidence bundle
    print("  📊 Evidence timeline:")
    print("    14:30:00 │ 💭 INTENT: Calculate sum")
    print("    14:30:01 │ ⚡ EXECUTION: math:sum_range")
    print("    14:30:02 │ ✅ RESULT: 5050")
    print("    14:30:03 │ 🪦 TOMBSTONE: Agent stopped")
    print()
    
    print("="*60)
    print("✅ Basic usage complete!")
    print("="*60)
    print()
    print("Next steps:")
    print("  - Review evidence: .guardclaw/ledger/observations/")
    print("  - Replay timeline: guardclaw replay evidence-bundle/")
    print("  - Switch to Strict mode: export GUARDCLAW_MODE=strict")


if __name__ == "__main__":
    main()
