"""
File Operations Demo - Safe file access with GuardClaw.

This demo shows how GuardClaw provides accountability for
file system operations.
"""

import os
from pathlib import Path
from guardclaw.core.models import ActionType
from guardclaw.core.wrapper import ExecutionWrapper
from guardclaw.runtime.context import RuntimeContext


class FileOperationsDemo:
    """
    Demo: File operations with GuardClaw protection.
    
    Shows:
    - Reading files requires authorization
    - Writing files requires authorization
    - All operations are logged
    """
    
    def __init__(self, wrapper: ExecutionWrapper):
        """
        Initialize demo with wrapper.
        
        Args:
            wrapper: Configured ExecutionWrapper
        """
        self.wrapper = wrapper
    
    @property
    def read_file(self):
        """
        Protected file read operation.
        
        Returns:
            Decorated function for reading files
        """
        @self.wrapper.protect(
            action_type=ActionType.FILE_READ,
            target_resource="demo-file.txt",
            operation="read",
            agent_id="demo-agent"
        )
        def _read_file(filepath: str) -> str:
            """Read file contents."""
            with open(filepath, 'r') as f:
                return f.read()
        
        return _read_file
    
    @property
    def write_file(self):
        """
        Protected file write operation.
        
        Returns:
            Decorated function for writing files
        """
        @self.wrapper.protect(
            action_type=ActionType.FILE_WRITE,
            target_resource="demo-file.txt",
            operation="write",
            agent_id="demo-agent"
        )
        def _write_file(filepath: str, content: str) -> None:
            """Write content to file."""
            with open(filepath, 'w') as f:
                f.write(content)
        
        return _write_file
    
    def run_demo(self, demo_dir: Path):
        """
        Run the file operations demo.
        
        Args:
            demo_dir: Directory for demo files
        """
        print("\n" + "="*60)
        print("FILE OPERATIONS DEMO - GuardClaw Phase 1")
        print("="*60)
        
        # Create demo file
        demo_file = demo_dir / "demo-file.txt"
        demo_file.write_text("Original content")
        
        print(f"\n1. Reading file: {demo_file}")
        try:
            content = self.read_file(str(demo_file))
            print(f"   ✅ Read successful: {content!r}")
        except Exception as e:
            print(f"   ❌ Read failed: {e}")
        
        print(f"\n2. Writing to file: {demo_file}")
        try:
            self.write_file(str(demo_file), "Modified by GuardClaw!")
            print(f"   ✅ Write successful")
        except Exception as e:
            print(f"   ❌ Write failed: {e}")
        
        print(f"\n3. Verifying write:")
        new_content = demo_file.read_text()
        print(f"   File now contains: {new_content!r}")
        
        print(f"\n4. Checking ledger:")
        ledger_entries = len(self.wrapper.context.ledger.entries)
        print(f"   📜 Ledger has {ledger_entries} entries")
        
        print("\n" + "="*60)
        print("DEMO COMPLETE - All operations logged in ledger")
        print("="*60 + "\n")


def run_file_demo():
    """
    Standalone runner for file operations demo.
    """
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Setup policy
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
name: "file-demo-policy"
version: "1.0"
default_decision: "ALLOW"
rules: []
        """)
        
        # Setup context
        ledger_path = tmp_path / "ledger.json"
        context = RuntimeContext.from_config(
            policy_file=policy_file,
            ledger_path=ledger_path,
            executor_id="file-demo-executor"
        )
        
        # Create wrapper
        wrapper = ExecutionWrapper(context)
        
        # Run demo
        demo = FileOperationsDemo(wrapper)
        demo.run_demo(tmp_path)


if __name__ == "__main__":
    run_file_demo()
