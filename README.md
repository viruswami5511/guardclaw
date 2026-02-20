# GuardClaw

**DOI:** https://zenodo.org/records/18712808
**Published:** 2026-02-20  
**License:** CC-BY 4.0 (paper) / Apache 2.0 (code)

## 📄 Research Paper

**Replay-Bound Evidence: Cryptographic Accountability for Autonomous AI Systems**

A formal discussion draft proposing a cryptographic framework for auditable,
tamper-evident logging in autonomous AI agents.

- 📖 [Read the paper](docs/replay-bound-evidence-v1.0.md)
- 🏷️ Tagged release: `paper-v1.0`

> This paper introduces the concept of *Replay-Bound Evidence* — a mechanism
> to ensure every AI action is signed, chained, and verifiable against replay attacks.

---

Cryptographic evidence ledger for autonomous agent accountability

Autonomous systems require stronger guarantees than mutable logs can provide.  
GuardClaw implements the minimal cryptographic properties required for replay-bound, verifiable agent evidence.

GuardClaw records what AI agents do and makes those records cryptographically verifiable.

It does not block execution.  
It does not enforce policy.  
It does not require SaaS infrastructure.  

It provides verifiable evidence of what was recorded.

📄 *Protocol specification:*  
https://github.com/viruswami5511/guardclaw/blob/master/docs/PROTOCOL.md  

🔒 *Security model:*  
https://github.com/viruswami5511/guardclaw/blob/master/SECURITY.md  

⚠️ *Threat model:*  
https://github.com/viruswami5511/guardclaw/blob/master/THREAT_MODEL.md  

---

## Status

*Alpha (v0.1.2)*

GuardClaw is experimental software.  
Breaking changes may occur before v1.0.

Appropriate for development, research, and low-risk automation.  
Not recommended for high-risk production systems.

Explicit guarantees and limitations are defined in the Security and Threat Model documents linked above.

---

## What GuardClaw Provides

- Ed25519 cryptographic signing  
- Deterministic canonical JSON serialization  
- Ledger-local nonce-based replay detection  
- Tamper-evident verification  
- Offline verification (no network required)  
- CLI replay inspection  

---

## What GuardClaw Does NOT Provide

- Policy enforcement  
- Authorization engine  
- Settlement or reconciliation logic  
- Hash-chained ledger structure  
- Durable replay state across restarts  
- Distributed consensus  
- Key rotation management  
- Trusted timestamp authority  
- File deletion detection  
- Cross-system replay prevention  

GuardClaw is an evidence layer, not a control plane.

---

## Installation

```bash
pip install guardclaw
```

For development:

```bash
git clone https://github.com/viruswami5511/guardclaw.git
cd guardclaw
pip install -e .
```
---

## Quick Start

### 1. Generate a Signing Key

```python
from guardclaw.core.crypto import Ed25519KeyManager

key_manager = Ed25519KeyManager.generate()
```

### 2. Start an Evidence Emitter

```python
from guardclaw.core.emitter import EvidenceEmitter

emitter = EvidenceEmitter(
    key_manager=key_manager,
    ledger_path=".guardclaw/ledger"
)

emitter.start()
```

### 3. Observe Agent Actions

```python
from guardclaw.core.observers import Observer

observer = Observer("observer-1")
observer.set_emitter(emitter)

observer.on_intent("agent-1", "analyze_data")
observer.on_execution("agent-1", "analyze_data")
observer.on_result("agent-1", "analyze_data", "completed")
```

Each event:

- Receives a cryptographically secure 32-character hexadecimal nonce  
- Is serialized deterministically  
- Is signed using Ed25519  
- Is appended to the ledger  

### 4. Stop the Emitter

```python
emitter.stop()
```

Ledger output is written to .guardclaw/ledger/ as signed JSONL events.

---

## Verifying a Ledger

```bash
guardclaw replay .guardclaw/ledger
```

Verification performs:

- Schema validation  
- Nonce validation  
- Canonical reconstruction  
- Signature verification  
- Ledger-local replay detection  

Verification can be performed offline using only:

- The ledger file  
- The public key  

---

## Protocol Overview (v0.1.2)

Each event conforms to:

```json
{
  "event_id": "string",
  "timestamp": "ISO-8601 UTC",
  "event_type": "intent | execution | result | failure",
  "subject_id": "string",
  "action": "string",
  "nonce": "32 hex characters",
  "correlation_id": "string | null",
  "metadata": "object | null"
}
```

### Nonce Constraints

- MUST exist  
- MUST be 32 hexadecimal characters  
- MUST be unique per subject_id  

Duplicate nonce within the same subject is considered replay.

Replay state in v0.1.2 is memory-local and not durable across restarts.

See full specification:  
https://github.com/viruswami5511/guardclaw/blob/master/docs/PROTOCOL.md

---

## Security Summary

If private keys remain secure:

- Signed events cannot be modified without detection  
- Events are cryptographically attributable  
- Replay within a ledger is detectable  
- Verification fails loudly on tampering  
- Verification works offline  

GuardClaw does not guarantee:

- Prevention of malicious behavior  
- Durable replay protection  
- Cross-system replay prevention  
- Absolute timestamp correctness  
- Protection against compromised keys  
- Immutable storage  

Full analysis:  
https://github.com/viruswami5511/guardclaw/blob/master/SECURITY.md  
https://github.com/viruswami5511/guardclaw/blob/master/THREAT_MODEL.md  

---

## Testing

Run replay protection tests:

```bash
python -m pytest tests/unit/test_replay_protection.py -v
```

Expected result:

```text
16 passed
```
---

## Roadmap

Planned future areas (non-binding):

- Hash chaining  
- Durable replay protection  
- Key rotation audit events  
- External timestamp anchoring  
- Delegated authority model  

These are not part of v0.1.2 guarantees.

---

## When to Use GuardClaw

Appropriate for:

- Development environments  
- Internal AI tooling  
- Research prototypes  
- Low-risk automation  
- Audit experimentation  

Not recommended for production use in:

- Financial settlement systems  
- Critical infrastructure  
- Regulatory-grade audit without additional controls  
- Long-term archival systems  
- High-risk autonomous systems  

---

## Contributing

Contributions are welcome.

Before submitting:

- Read the Protocol specification  
- Read the Security model  
- Include tests  
- Maintain scope discipline  

---

## License

Apache-2.0

---

## Philosophy

GuardClaw does not promise perfect safety.

It provides cryptographic evidence of what was recorded.

Nothing more. Nothing less.
