"""
File Operations Demo - Safe file access with GuardClaw.
"""

import os
from pathlib import Path
from guardclaw.core.action_types import ActionType
from guardclaw.core.wrapper import ExecutionWrapper
from guardclaw.runtime.context import RuntimeContext

SEP = "-" * 60


class FileOperationsDemo:

    def __init__(self, wrapper: ExecutionWrapper):
        self.wrapper = wrapper

    def run_demo(self, demo_dir: Path):
        print(SEP)
        print("FILE OPERATIONS DEMO - GuardClaw")
        print(SEP)

        demo_file = demo_dir / "demo-file.txt"
        demo_file.write_text("Original content")

        @self.wrapper.protect(
            action_type=ActionType.FILE_READ,
            target_resource="demo-file.txt",
            operation="read",
            agent_id="demo-agent"
        )
        def read_file(filepath: str) -> str:
            with open(filepath, "r") as f:
                return f.read()

        @self.wrapper.protect(
            action_type=ActionType.FILE_WRITE,
            target_resource="demo-file.txt",
            operation="write",
            agent_id="demo-agent"
        )
        def write_file(filepath: str, content: str) -> None:
            with open(filepath, "w") as f:
                f.write(content)

        print("
1. Reading file...")
        try:
            content = read_file(str(demo_file))
            print("   OK: " + repr(content))
        except Exception as e:
            print("   FAIL: " + str(e))

        print("
2. Writing to file...")
        try:
            write_file(str(demo_file), "Modified by GuardClaw!")
            print("   OK: Write successful")
        except Exception as e:
            print("   FAIL: " + str(e))

        print("
3. Verifying write...")
        print("   File now contains: " + repr(demo_file.read_text()))

        print(SEP)
        print("DEMO COMPLETE")
        print(SEP)


def run_file_demo():
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        ledger_path = tmp_path / "ledger.jsonl"
        context = RuntimeContext.from_config(
            ledger_path=ledger_path,
            executor_id="file-demo-executor"
        )
        wrapper = ExecutionWrapper(context)
        demo = FileOperationsDemo(wrapper)
        demo.run_demo(tmp_path)


if __name__ == "__main__":
    run_file_demo()
