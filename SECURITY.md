# GuardClaw Security Model

Status: Alpha  
Version: 0.1.3

## Overview

GuardClaw v0.1.3 is a cryptographic evidence ledger for autonomous agent accountability.

It provides:

* Signed event emission
* Ledger-local nonce-based replay detection
* Tamper-evident verification
* Offline verifiability

It does not enforce policy or prevent execution.

## Guarantees

If private keys remain secure:

* Signed events cannot be modified without detection
* Events are cryptographically attributable
* Ledger-local replay is detectable
* Verification can be performed offline

## Limitations

GuardClaw v0.1.3 does NOT provide:

* Durable replay protection across restarts
* Hash chaining between ledger files
* Distributed consensus
* External timestamp authority
* Key rotation mechanisms
* Key compromise detection
* File deletion detection
* Policy enforcement engine

Replay detection is ledger-local and memory-bound.  
Keys are file-based.  
Timestamps rely on the system clock.

## Suitable Use Cases

* Development environments
* Internal tooling
* Low-risk automation
* Research prototypes

## Not Suitable For (Without Additional Controls)

* Financial settlement systems
* Critical infrastructure
* Regulatory-grade audit environments
* High-value adversarial deployments

## Scope Boundary

GuardClaw prioritizes verifiability over enforcement.

It proves what was recorded.  
It does not prevent actions.

## Disclosure

GuardClaw v0.1.3 is experimental software. It is intended as a foundational
accountability layer, not a complete security system. Use additional controls
where required.

