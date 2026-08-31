# GuardClaw New — Cryptographic AI Audit Trail

## Project Root
C:\Users\rohan\OneDrive\Desktop\GuardClaw New\
WSL: /mnt/c/Users/rohan/OneDrive/Desktop/GuardClaw New/

## Overview
GuardClaw creates a cryptographic evidence ledger for AI system actions. Every inference, decision, and output is hashed, signed, and verifiable.

## Critical Rules
- Never modify vault entries after creation — append-only
- Every action must be provable after the fact
- Tamper detection is the core value proposition
- Security before convenience

## Hermes Agent Safety Protocol (CRITICAL — Read Before ANY Edits)
- Read this entire file before making ANY edits.
- This project is a cryptographic security system. A single mistake breaks trust guarantees.
- NEVER delete or modify vault data. NEVER weaken hash chains.
- Read SPEC.md and THREAT_MODEL.md before making architectural changes.
- session_search for recent context if this is a new session or switching from another project.
- If unsure about anything, ask the user before changing.
- NEVER delete code that "looks unnecessary" — only remove after fully understanding what it does.
- This rule applies even when using Claude Code as a subagent: delegate tasks but enforce the same safety.
