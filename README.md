# GuardClaw

**Cryptographically signed, replay-protected evidence ledger for AI agents**

GuardClaw records what AI agents do — and makes those records cryptographically verifiable.

It does not block execution.  
It does not enforce policy.  
It does not require SaaS.  

It proves what was recorded.

---

## Status: Alpha (v0.1.0)

GuardClaw v0.1.0 is an **experimental accountability substrate**.

It provides a minimal, strict, cryptographic event ledger with replay detection.

Breaking changes may occur before v1.0.

Not recommended for high-risk production systems.

See `SECURITY.md` and `THREAT_MODEL.md` for full scope boundaries.

---

## What GuardClaw Provides

- ✅ Ed25519 cryptographic signing  
- ✅ Canonical JSON serialization  
- ✅ Per-agent nonce-based replay detection  
- ✅ Tamper-evident verification  
- ✅ Offline verification (no network required)  
- ✅ CLI replay inspection  

---

## What GuardClaw Does NOT Provide

- ❌ Policy enforcement  
- ❌ Authorization engine  
- ❌ Settlement or reconciliation logic  
- ❌ Hash-chained ledger  
- ❌ Durable replay memory  
- ❌ Distributed consensus  
- ❌ Key rotation system  
- ❌ Timestamp authority  

GuardClaw is an evidence layer — not a control plane.

---

# Installation

```bash
pip install guardclaw

For development:
git clone https://github.com/YOUR_USERNAME/guardclaw.git
cd guardclaw
pip install -e .


Quick Start
1️⃣ Generate a Signing Key
from guardclaw.core.crypto import Ed25519KeyManager

key_manager = Ed25519KeyManager.generate()


2️⃣ Start an Evidence Emitter
from guardclaw.core.emitter import EvidenceEmitter

emitter = EvidenceEmitter(
    key_manager=key_manager,
    ledger_path=".guardclaw/ledger"
)

emitter.start()


3️⃣ Observe Agent Actions
from guardclaw.core.observers import Observer

observer = Observer("observer-1")
observer.set_emitter(emitter)

observer.on_intent("agent-1", "analyze_data")
observer.on_execution("agent-1", "analyze_data")
observer.on_result("agent-1", "analyze_data", "completed")

Each event:

Receives a cryptographically secure 32-hex nonce
Is serialized canonically
Is signed using Ed25519
Is appended to the ledger


4️⃣ Stop the Emitter
emitter.stop()

Ledger is written to:
.guardclaw/ledger/

Each line is a signed event (JSONL).

Verify a Ledger
GuardClaw provides a CLI replay command:
guardclaw replay .guardclaw/ledger

Replay performs:

Schema validation
Nonce validation
Canonical JSON reconstruction
Signature verification
Replay detection (per-agent)

Example output:
============================================================
GuardClaw Replay
============================================================

10:30:45.123 │ INTENT      │ agent-1 │ analyze_data │ ✅ VALID
10:30:45.234 │ EXECUTION   │ agent-1 │ analyze_data │ ✅ VALID
10:30:45.345 │ RESULT      │ agent-1 │ analyze_data │ ✅ VALID

Summary:
Total events: 3
Valid: 3
Invalid: 0
Replays detected: 0

Verification can be performed offline using only:

The ledger file
The public key


Protocol Overview (v0.1.0)
Each event has this schema:
{
    "event_id": str,
    "timestamp": str,          # ISO 8601 UTC
    "event_type": str,
    "subject_id": str,
    "action": str,
    "nonce": str,              # REQUIRED (32 hex characters)
    "correlation_id": str | None,
    "metadata": dict | None
}

Nonce requirements:

MUST exist
MUST be 32 hexadecimal characters
MUST be unique per subject_id

Duplicate nonce within same subject_id is considered replay.
Replay detection is memory-local in v0.1.0.
See PROTOCOL.md for full specification.

Security Model (Short Version)
GuardClaw Guarantees
If private keys are secure:

Signed events cannot be modified without detection
Events are cryptographically attributable
Same-ledger replay is detectable
Verification fails loudly on tampering
Verification works offline

GuardClaw Does NOT Guarantee

Prevention of malicious behavior
Durable replay protection across restarts
Cross-system replay prevention
Trusted timestamps
File deletion detection
Protection against stolen keys

Full analysis: SECURITY.md and THREAT_MODEL.md

Testing
Run replay protection tests:
python -m pytest tests/unit/test_replay_protection.py -v

Expected:
16 passed


Roadmap (Non-Binding)
Planned future areas:

Hash chaining
Durable replay protection
Key rotation audit events
External timestamp anchoring
Delegated authority model

These are not part of v0.1.0 guarantees.

When to Use GuardClaw (v0.1.0)
Appropriate:

Development environments
Internal AI tooling
Research prototypes
Low-risk automation
Audit experiments

Not appropriate:

Financial systems
Critical infrastructure
Legal compliance use cases
Long-term archival
High-risk autonomous agents


Contributing
Contributions welcome.
Before submitting:

Read PROTOCOL.md
Read SECURITY.md
Include tests
Avoid expanding guarantees beyond documented scope


License
Apache-2.0

Philosophy
GuardClaw does not promise perfect safety.
It promises cryptographic evidence of what was recorded.
Nothing more. Nothing less.
