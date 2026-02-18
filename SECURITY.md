# GuardClaw Security Model (v0.1.1)

Status: Alpha  
Version: 0.1.1

---

## Overview

GuardClaw v0.1.1 is a cryptographic evidence ledger for autonomous agent accountability.

It provides:

- Signed event emission
- Ledger-local nonce-based replay detection
- Tamper-evident verification
- Offline verifiability

It does not enforce policy or prevent execution.

---

## Guarantees

If private keys remain secure:

- Signed events cannot be modified without detection
- Events are cryptographically attributable
- Ledger-local replay is detectable
- Verification can be performed offline

---

## Limitations

GuardClaw v0.1.1 does NOT provide:

- Durable replay protection
- Hash chaining
- Distributed consensus
- Trusted timestamp authority
- Key rotation mechanisms
- Key compromise detection
- File deletion detection
- Enforcement or blocking logic

Replay state is memory-local only.  
Timestamps rely on system clock.  
Keys are file-based in v0.1.1.

---

## Scope Boundary

GuardClaw prioritizes verifiability over enforcement.  
It proves what was recorded.  
It does not prevent actions.