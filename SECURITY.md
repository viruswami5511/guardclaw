
# GuardClaw Security Model (v0.1.2)
Status: Alpha

Overview

GuardClaw v0.1.2 is a cryptographically signed event ledger for AI agent accountability.
It provides tamper detection and replay detection within a ledger.
GuardClaw is an accountability layer. It observes and proves. It does not enforce policy or block execution.


## Overview

GuardClaw v0.1.2 is a cryptographic evidence ledger for autonomous agent accountability.

It provides:

- Signed event emission
- Ledger-local nonce-based replay detection
- Tamper-evident verification
- Offline verifiability

It does not enforce policy or prevent execution.

---

## Guarantees

Guarantees

If private keys remain secure:
Signed events cannot be modified without detection
Events are cryptographically attributable
Replay within a ledger is detectable
Verification can be performed offline


- Signed events cannot be modified without detection
- Events are cryptographically attributable
- Ledger-local replay is detectable
- Verification can be performed offline

---

## Limitations

GuardClaw v0.1.2 does NOT provide:

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
Keys are file-based in v0.1.2.

## Limitations (v0.1.2 Scope)-

GuardClaw v0.1.2 does not provide:

Durable replay protection across restarts
Hash chaining between ledger files
Distributed consensus
External timestamp authority
Key rotation mechanisms
Key compromise detection
File deletion detection
Policy enforcement engine
Replay detection is ledger-local and memory-bound.
Keys are file-based.
Timestamps rely on the system clock.

## Suitable Use Cases-
Development environments
Internal tooling
Low-risk automation
Research prototypes


Not Suitable For (Without Additional Controls) -

Financial settlement systems
Critical infrastructure
Regulatory-grade audit environments
High-value adversarial deployments

## Scope Boundary

GuardClaw prioritizes verifiability over enforcement.  
It proves what was recorded.  
It does not prevent actions.

Disclosure

GuardClaw v0.1.2 is experimental software.
It is intended as a foundational accountability layer, not a complete security system.
Use additional controls where required.

