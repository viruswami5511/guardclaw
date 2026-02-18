# GuardClaw Protocol Specification (v0.1.1)

Status: Alpha

---

## 1. Purpose

GuardClaw is a cryptographic evidence ledger for autonomous agent accountability.

It provides:

- Signed event emission
- Deterministic canonical serialization
- Ledger-local nonce-based replay detection
- Tamper-evident verification
- Offline verifiability

GuardClaw v0.1.1 does NOT implement:

- Policy enforcement
- Authorization engines
- Settlement logic
- Distributed consensus
- Hash chaining
- Durable replay memory

GuardClaw is an accountability substrate.

---

## 2. Event Schema

An ObservationEvent represents a single recorded action.

```python
{
    "event_id": str,
    "timestamp": str,          # ISO 8601 UTC
    "event_type": str,         # intent | execution | result | failure
    "subject_id": str,
    "action": str,
    "nonce": str,              # REQUIRED, 32 hex characters
    "correlation_id": str | None,
    "metadata": dict | None
}



## Field Requirements-

event_id MUST be unique within a ledger.
timestamp MUST be ISO 8601 UTC.
event_type MUST be one of: intent | execution | result | failure.
nonce MUST exist.
nonce MUST be exactly 32 hexadecimal characters.
nonce MUST be cryptographically random.
Missing or invalid nonce results in validation failure.


## 3. Canonical Serialization

GuardClaw uses deterministic canonical JSON encoding:
UTF-8 encoding
Sorted dictionary keys
No insignificant whitespace
Canonical encoding ensures identical payloads produce identical hashes.
The nonce is part of the canonical payload and protected by signature.


## 4. Signing Model

Algorithm: Ed25519
Payload: Canonical JSON bytes of ObservationEvent
Signature format: Hex string
Any modification invalidates the signature.


## 5. Replay Detection

Replay detection in v0.1.1 is nonce-based.

*Rules:*
* Nonce uniqueness is scoped per subject_id.
* Duplicate nonce for the same subject is considered replay.
* Replay detection occurs during verification.
* Replay tracking is memory-local and not durable across restarts.

## 6. Ledger Structure

JSONL files
Append-only writes
Each line is a SignedObservation
No hash chaining
No Merkle tree
No sequence numbers

Ledger integrity relies solely on signature verification.
File deletion is not detectable in v0.1.1.


## 7. Verification Model

Verification consists of:
Schema validation
Nonce validation
Canonical JSON reconstruction
Signature verification
Ledger-local replay detection

Verification requires only:

Ledger file
Public key

Offline verification is supported.


## 8. Security Properties

If private keys remain secure:

Signed events cannot be modified without detection
Events are cryptographically attributable
Ledger-local replay is detectable
Verification fails loudly on tampering

Non-Guarantees:

Durable replay protection
Hash chaining
Distributed consensus
Trusted timestamps
Key rotation
File deletion detection
Cross-system replay prevention


## 9. Versioning

0.x.x — Experimental
1.x.x — Stable protocol guarantees

Breaking protocol changes may occur before v1.0.


## 10. Design Philosophy

GuardClaw prioritizes:

Explicit guarantees
Loud failure over silent corruption
Verifiability over convenience
Narrow, correct guarantees over broad promises

GuardClaw proves what was recorded.
It does not attempt to prevent actions.