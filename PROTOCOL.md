## 1. Purpose

GuardClaw is a cryptographically signed, replay-protected evidence ledger for AI agents.

It provides:

- Signed event emission
- Canonical serialization
- Per-agent replay protection (nonce-based)
- Tamper-evident verification
- Offline verifiability

GuardClaw v0.1.0 does NOT implement:

- Policy enforcement
- Authorization engines
- Settlement logic
- Distributed consensus
- Hash chaining
- Durable replay memory

GuardClaw is an accountability substrate.

---

## 2. Core Concepts

### 2.1 ObservationEvent

An `ObservationEvent` represents a single recorded action or state transition emitted by an agent.

### Schema

```python
{
    "event_id": str,
    "timestamp": str,          # ISO 8601 UTC
    "event_type": str,         # intent | execution | result | failure | delegation | heartbeat
    "subject_id": str,         # Agent identity
    "action": str,
    "nonce": str,              # REQUIRED, 32 hex characters
    "correlation_id": str | None,
    "metadata": dict | None
}

Field Requirements

event_id MUST be unique within a ledger.
timestamp MUST be ISO 8601 formatted UTC string.
event_type MUST be one of the supported types.
subject_id identifies the emitting agent.
nonce is REQUIRED.
nonce MUST be exactly 32 hexadecimal characters.
nonce MUST be cryptographically random.
Missing or invalid nonce results in validation failure.


3. Canonical Serialization
GuardClaw uses deterministic canonical JSON encoding:

UTF-8 encoding
Sorted dictionary keys
No insignificant whitespace
Stable field ordering

Canonical encoding ensures identical payloads produce identical hashes.
The nonce is part of the canonical payload and therefore protected by signature.

4. SignedObservation
Each ObservationEvent is wrapped in a SignedObservation.
Signing Algorithm

Algorithm: Ed25519
Payload: Canonical JSON bytes of ObservationEvent
Signature format: Hex string

Signature verification requires:

Reconstructing canonical JSON
Verifying against the signer's public key

Any modification of:

nonce
timestamp
action
metadata
or any field

invalidates the signature.

5. Replay Protection
Replay protection in v0.1.0 is nonce-based.
Rules

Nonce uniqueness is scoped per subject_id.
Duplicate nonce for the same subject_id is considered a replay.
Replay detection occurs during verification.

Limitations

Replay tracking is memory-local.
Replay state is not durable across restarts.
Replay detection does not extend across separate systems.


6. Ledger Structure (v0.1.0)
Ledger storage model:

JSONL files
Append-only writes
Each line is a SignedObservation
No internal hash chaining
No Merkle tree
No sequence numbers

Ledger integrity relies on signature verification only.
File deletion is not detectable in v0.1.0.

7. Verification Model
Verification consists of:

Schema validation
Nonce validation
Canonical JSON reconstruction
Signature verification
Replay detection (per-agent nonce check)

Verification can be performed offline using only:

Ledger file
Public key


8. Security Properties
Guarantees
If private keys remain secure:

Signed events cannot be modified without detection
Events are cryptographically attributable
Replay within a ledger is detectable
Signature tampering fails loudly
Verification is offline-capable

Non-Guarantees
GuardClaw v0.1.0 does NOT provide:

Durable replay protection
Hash chaining
Distributed consensus
Trusted timestamp authority
Key rotation mechanisms
Key compromise detection
Enforcement or blocking logic
Authorization proofs
Settlement reconciliation
Cross-system replay protection


9. Cryptography

Signing: Ed25519 (RFC 8032)
Hashing: SHA-256 (via canonical JSON encoding)
Encoding: UTF-8 JSON
Key storage: File-based (v0.1.0)

Keys MUST be protected by the host system.
Compromised keys invalidate trust guarantees.

10. Versioning
GuardClaw follows semantic versioning:

0.x.x — Experimental (breaking changes possible)
1.x.x — Stable protocol guarantees

Breaking protocol changes may occur before v1.0.

11. Design Philosophy
GuardClaw prioritizes:

Explicit guarantees
Loud failure over silent corruption
Minimal trust assumptions
Verifiability over convenience

GuardClaw does not attempt to prevent actions.
It proves what was recorded.

12. Future Directions (Non-Binding)
Possible future enhancements include:

Hash chaining
Durable replay protection
Key rotation audit events
External timestamp anchoring
Delegated authority model
Merkle tree ledger structure

These are NOT part of v0.1.0 guarantees.

End of Specification.

