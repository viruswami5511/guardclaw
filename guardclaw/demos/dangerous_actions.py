"""
Dangerous Actions Demo - GuardClaw prevents unauthorized destruction.
"""

import os
from pathlib import Path
from guardclaw.core.action_types import ActionType
from guardclaw.core.wrapper import ExecutionWrapper, WrapperError
from guardclaw.runtime.context import RuntimeContext

SEP = "-" * 60


class DangerousActionsDemo:

    def __init__(self, wrapper: ExecutionWrapper):
        self.wrapper = wrapper

    def run_demo(self, demo_dir: Path):
        print(SEP)
        print("DANGEROUS ACTIONS DEMO - GuardClaw")
        print(SEP)

        safe_file = demo_dir / "safe-to-delete.txt"
        safe_file.write_text("This file can be deleted")

        print("
1. Authorized deletion...")

        @self.wrapper.protect(
            action_type=ActionType.FILE_DELETE,
            target_resource=str(safe_file),
            operation="delete",
            agent_id="dangerous-agent"
        )
        def delete_file(filepath: str) -> None:
            if os.path.exists(filepath):
                os.remove(filepath)
            else:
                raise FileNotFoundError("File not found: " + filepath)

        try:
            delete_file(str(safe_file))
            print("   OK: Deleted. File exists: " + str(safe_file.exists()))
        except WrapperError as e:
            print("   BLOCKED: " + str(e))

        print("
2. Execution fails but settlement still runs...")
        nonexistent = demo_dir / "doesnt-exist.txt"

        @self.wrapper.protect(
            action_type=ActionType.FILE_DELETE,
            target_resource=str(nonexistent),
            operation="delete",
            agent_id="dangerous-agent"
        )
        def delete_nonexistent(filepath: str) -> None:
            if os.path.exists(filepath):
                os.remove(filepath)
            else:
                raise FileNotFoundError("File not found: " + filepath)

        try:
            delete_nonexistent(str(nonexistent))
        except WrapperError as e:
            print("   FAIL recorded: " + str(e))

        print(SEP)
        print("KEY INSIGHT: Even failed actions create accountability")
        print(SEP)


def run_dangerous_demo():
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        ledger_path = tmp_path / "ledger.jsonl"
        context = RuntimeContext.from_config(
            ledger_path=ledger_path,
            executor_id="dangerous-demo-executor"
        )
        wrapper = ExecutionWrapper(context)
        demo = DangerousActionsDemo(wrapper)
        demo.run_demo(tmp_path)


if __name__ == "__main__":
    run_dangerous_demo()
