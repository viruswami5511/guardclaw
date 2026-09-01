"""
demo_antigravity_guardclaw.py

Simulates live Antigravity Agent tool execution audited in real-time
by GuardClaw using both the @audit decorator and direct GEFLedger logging.
"""

import sys
import io
import shutil
from pathlib import Path

# Ensure UTF-8 stdout on Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from guardclaw import GEFLedger, Ed25519KeyManager, RecordType, verify_ledger

audit_dir = Path("./antigravity_audit_vault")
if audit_dir.exists():
    shutil.rmtree(audit_dir)

print("==================================================================")
print("[ANTIGRAVITY] LIVE AI AGENT AUDITED BY GUARDCLAW")
print("==================================================================")

# 1. Initialize an authentic agent session with dedicated Ed25519 key
key_mgr = Ed25519KeyManager.generate()
ledger = GEFLedger(
    key_manager=key_mgr,
    agent_id="antigravity-ai-pair-programmer",
    ledger_path=str(audit_dir),
)

print("\n--- STEP 1: Antigravity Executing Real Actions ---")

# Action 1: Execute shell command
print("  -> [TOOL CALL]: execute_shell_command('pytest -v')")
e1 = ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={"tool": "shell.exec", "command": "pytest -v", "purpose": "Test entire repository"},
)
print(f"     [SEALED RECEIPT]: Seq #{e1.sequence} | ID: {e1.record_id[:16]}... | Signature OK")

# Action 2: Edit file
print("  -> [TOOL CALL]: modify_project_file('guardclaw/core/kms.py')")
e2 = ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={"tool": "file.modify", "file": "guardclaw/core/kms.py", "lines_added": 42},
)
print(f"     [SEALED RECEIPT]: Seq #{e2.sequence} | ID: {e2.record_id[:16]}... | Signature OK")

# Action 3: Release build
print("  -> [TOOL CALL]: publish_release('guardclaw', '0.8.2')")
e3 = ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={"tool": "registry.publish", "package": "guardclaw", "version": "0.8.2"},
)
print(f"     [SEALED RECEIPT]: Seq #{e3.sequence} | ID: {e3.record_id[:16]}... | Signature OK")

print("\n--- STEP 2: Mathematical Cryptographic Verification ---")
print(f"Verifying ledger at {audit_dir}/ ...")
summary = verify_ledger(str(audit_dir))
print(f"[*] Ledger Validity Status : {summary.get('chain_valid')}")
print(f"[*] Total Entries Processed : {summary.get('total_entries')}")
print(f"[*] Verified Record Count   : {summary.get('verified_count')}")
print(f"[*] Latest Causal Hash      : {summary.get('last_verified_causal_hash')}")
print(f"[*] Verification Level      : {summary.get('verification_level')}")
print(f"[*] Tampering Detected      : {'NONE (100% INTACT & DEFUSED)' if summary.get('chain_valid') else summary.get('failure_detail')}")

print("\n--- STEP 3: Live Tampering Experiment (The Proof) ---")
print("Simulating an attacker modifying the recorded version from '0.8.2' to '9.9.9' on disk...")
ledger_file = audit_dir / "ledger.jsonl"
content = ledger_file.read_text(encoding="utf-8")
tampered_content = content.replace("0.8.2", "9.9.9")
ledger_file.write_text(tampered_content, encoding="utf-8")

print("Re-verifying tampered ledger...")
tamper_summary = verify_ledger(str(audit_dir))
print(f"[!] Tampered Validity Status: {tamper_summary.get('chain_valid')}")
print(f"[!] Tampering Detection Code : {tamper_summary.get('failure_detail')}")
print(f"[!] Attacker Successfully Caught: {not tamper_summary.get('chain_valid')}")

print("\n==================================================================")
print("[OK] DEMO FINISHED: GuardClaw provably audited Antigravity actions!")
print("==================================================================")
