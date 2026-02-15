# GuardClaw Security Model (v0.1.0)

**Status:** Alpha  
**Version:** 0.1.0  

---

## Overview

GuardClaw v0.1.0 is a cryptographically signed event ledger for AI accountability.

It detects tampering and replay within a ledger.

It does not enforce policy or prevent execution.

---

## Guarantees

If private keys remain secure:

- Signed events cannot be modified without detection
- Events are cryptographically attributable
- Replay within a ledger is detectable
- Verification can be performed offline

---

## Limitations

GuardClaw v0.1.0 does NOT provide:

- Durable replay protection
- Hash chaining
- Distributed consensus
- Timestamp authority
- Key rotation
- Key compromise detection
- File deletion detection
- Enforcement engine

Replay state is memory-local only.

Keys are file-based.

Timestamps rely on system clock.

---

## Suitable Use Cases

- Development environments
- Internal tooling
- Low-risk automation
- Research prototypes

---

## Not Suitable For

- Financial settlement systems
- Critical infrastructure
- Regulatory-grade audit without additional controls
- High-value adversarial environments

---

## Disclosure

GuardClaw v0.1.0 is experimental software.

Use at your own risk.