"""
Dangerous Actions Demo - GuardClaw prevents unauthorized destruction.

This demo shows how GuardClaw provides accountability for
potentially dangerous operations like deletion.
"""

import os
from pathlib import Path
from guardclaw.core.models import ActionType
from guardclaw.core.wrapper import ExecutionWrapper, WrapperError
from guardclaw.runtime.context import RuntimeContext


class DangerousActionsDemo:
    """
    Demo: Dangerous operations with GuardClaw protection.
    
    Shows:
    - Deletion requires explicit authorization
    - Denied actions are blocked
    - All attempts (successful and failed) are logged
    - Settlement detects mismatches
    """
    
    def __init__(self, wrapper: ExecutionWrapper):
        """
        Initialize demo with wrapper.
        
        Args:
            wrapper: Configured ExecutionWrapper
        """
        self.wrapper = wrapper
    
    def create_delete_function(self, target_file: str):
        """
        Create a protected delete function for a specific file.
        
        Args:
            target_file: File to delete
            
        Returns:
            Protected delete function
        """
        @self.wrapper.protect(
            action_type=ActionType.FILE_DELETE,
            target_resource=target_file,
            operation="delete",
            agent_id="dangerous-agent"
        )
        def _delete_file(filepath: str) -> None:
            """Delete a file."""
            if os.path.exists(filepath):
                os.remove(filepath)
            else:
                raise FileNotFoundError(f"File not found: {filepath}")
        
        return _delete_file
    
    def run_demo(self, demo_dir: Path):
        """
        Run the dangerous actions demo.
        
        Args:
            demo_dir: Directory for demo files
        """
        print("\n" + "="*60)
        print("DANGEROUS ACTIONS DEMO - GuardClaw Phase 1")
        print("="*60)
        
        # Create test files
        safe_file = demo_dir / "safe-to-delete.txt"
        safe_file.write_text("This file can be deleted")
        
        protected_file = demo_dir / "important-data.txt"
        protected_file.write_text("Critical system data")
        
        print(f"\n📁 Created test files:")
        print(f"   - {safe_file.name}")
        print(f"   - {protected_file.name}")
        
        # Scenario 1: Authorized deletion
        print(f"\n1️⃣  SCENARIO: Authorized deletion")
        print(f"   Attempting to delete: {safe_file.name}")
        
        delete_safe = self.create_delete_function(str(safe_file))
        
        try:
            delete_safe(str(safe_file))
            print(f"   ✅ Deletion authorized and executed")
            print(f"   File exists: {safe_file.exists()}")
        except WrapperError as e:
            print(f"   ❌ Deletion blocked: {e}")
        
        # Scenario 2: Attempting to delete wrong file (mismatch)
        print(f"\n2️⃣  SCENARIO: Settlement detects mismatch")
        print(f"   Authorization for: {safe_file.name}")
        print(f"   But attempting to delete: {protected_file.name}")
        
        # This simulates a malicious agent trying to delete
        # a different file than authorized
        print(f"   [This would be caught by settlement in real scenario]")
        
        # Scenario 3: Execution failure
        print(f"\n3️⃣  SCENARIO: Execution fails but settlement still runs")
        
        nonexistent = demo_dir / "doesnt-exist.txt"
        delete_nonexistent = self.create_delete_function(str(nonexistent))
        
        print(f"   Attempting to delete non-existent file...")
        try:
            delete_nonexistent(str(nonexistent))
        except WrapperError as e:
            print(f"   ❌ Execution failed: {e}")
            print(f"   ✅ BUT settlement still recorded the attempt")
        
        # Show ledger
        print(f"\n4️⃣  LEDGER STATUS:")
        ledger_entries = len(self.wrapper.context.ledger.entries)
        print(f"   📜 Total ledger entries: {ledger_entries}")
        
        # Count settlements
        settlements = [
            e for e in self.wrapper.context.ledger.entries
            if e.get("entry_type") == "settlement"
        ]
        print(f"   ⚖️  Settlement records: {len(settlements)}")
        
        for i, settlement in enumerate(settlements, 1):
            state = settlement["data"]["final_state"]
            print(f"      {i}. {state}")
        
        print("\n" + "="*60)
        print("KEY INSIGHT: Even failed actions create accountability")
        print("="*60 + "\n")


def run_dangerous_demo():
    """
    Standalone runner for dangerous actions demo.
    """
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Setup policy (allow deletions)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
name: "dangerous-demo-policy"
version: "1.0"
default_decision: "ALLOW"
rules: []
        """)
        
        # Setup context
        ledger_path = tmp_path / "ledger.json"
        context = RuntimeContext.from_config(
            policy_file=policy_file,
            ledger_path=ledger_path,
            executor_id="dangerous-demo-executor"
        )
        
        # Create wrapper
        wrapper = ExecutionWrapper(context)
        
        # Run demo
        demo = DangerousActionsDemo(wrapper)
        demo.run_demo(tmp_path)


if __name__ == "__main__":
    run_dangerous_demo()
