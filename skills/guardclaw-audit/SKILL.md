---
name: guardclaw-audit
description: Cryptographically logs and verifies autonomous agent actions and tool calls into a tamper-evident, Ed25519 hash-chained GEF ledger.
---

# GuardClaw Cryptographic Audit Skill

Use this skill to create verifiable, tamper-evident execution receipts for any autonomous agent action (terminal commands, file modifications, API calls, and database transactions).

## When to Use This Skill
- **High-Stakes Operations**: The agent is executing irreversible commands (`rm`, `git reset`, database mutations, or deployment commands).
- **Compliance & Accountability**: The user requires offline proof that an agent's execution history has not been altered after the fact.
- **Flight Recorder**: Running long-running autonomous workflows overnight where a tamper-proof execution receipt is needed upon completion.

## How to Log Tool Actions

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

# 1. Initialize ledger for the current session
key_mgr = Ed25519KeyManager.generate()
ledger = GEFLedger(
    key_manager=key_mgr,
    agent_id="openclaw-autonomous-agent",
    ledger_path="./.agent_audit",
)

# 2. Record tool call intent before execution
intent = ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={
        "tool": "terminal.exec",
        "command": "git push origin main",
        "reasoning": "Deploying release candidate",
    },
)

# 3. Record tool execution result after execution
ledger.emit(
    record_type=RecordType.TOOL_RESULT,
    payload={
        "tool": "terminal.exec",
        "status": "success",
        "intent_record_id": intent.record_id,
    },
)
```

## How to Verify Audit Ledgers

Run the CLI verifier at any time to verify mathematical chain integrity:

```bash
guardclaw verify ./.agent_audit
```

Or verify programmatically:

```python
from guardclaw import verify_ledger

summary = verify_ledger("./.agent_audit")
if summary["chain_valid"]:
    print(f"Verified {summary['verified_count']} records with zero tampering.")
else:
    print(f"Tampering detected: {summary['failure_detail']}")
```
