# GuardClaw

**Cryptographic integrity for autonomous AI agents.**

[![PyPI](https://img.shields.io/pypi/v/guardclaw)](https://pypi.org/project/guardclaw)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-green)](SPEC.md)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/guardclaw)

---

## What Problem This Solves

AI agents are beginning to:

- Execute financial transactions  
- Modify production infrastructure  
- Invoke tools and shell commands autonomously  
- Operate without synchronous human review  

Traditional logs are mutable.  
Observability pipelines are not evidence.  
Database rows can be edited.  

If an AI agent makes a critical decision, how do you prove — cryptographically — what it actually did?

**GuardClaw implements GEF-SPEC-1.0**, a language-neutral protocol for generating:

> Tamper-evident, offline-verifiable execution ledgers.

No server required.  
No SaaS dependency.  
No central verifier.  

Just a file and a public key.

---

## What GuardClaw Is

GuardClaw is an **evidence layer**.

It provides:

- Deterministic canonicalization (RFC 8785 JCS)
- Causal hash chaining (SHA-256)
- Per-entry authenticity (Ed25519)
- Strict sequence monotonicity
- Replay and tamper detection
- Offline verification via CLI or library

It does **not**:

- Enforce policy
- Prevent actions
- Provide consensus
- Guarantee truthfulness
- Protect against private key compromise

It proves what was recorded — not whether it was wise.

---

## Integrity Model (Precise Definitions)

**Chain Integrity**  
= Correctness of `causal_hash` linkage  
Each entry must hash to the next.

```
causal_hash[N] = SHA256(JCS(entry[N-1].to_chain_dict()))
```
Genesis entry uses a 64-zero sentinel value.

**Ledger Integrity**  
= Chain integrity  
+ Strict sequence monotonicity (0 → N, no gaps)  
+ Schema validity  
+ Uniform GEF version  

If any of these fail, verification fails.

---

## Install

```bash
pip install guardclaw
```

Requires Python 3.9+

Core dependencies:

- `cryptography` (Ed25519)
- `jcs` (RFC 8785 canonicalization)
- `click` (CLI)

---

## 30-Second Example

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

# Generate signing key
key = Ed25519KeyManager.generate()

ledger = GEFLedger(
    key_manager=key,
    agent_id="agent-001",
    ledger_path="agent_ledger",
    mode="strict"   # strict = fsync enabled
)

ledger.emit(
    RecordType.EXECUTION,
    payload={"action": "shell.exec", "cmd": "rm temp.txt"}
)

ledger.emit(
    RecordType.RESULT,
    payload={"status": "success"}
)

ledger.close()

print("Chain valid:", ledger.verify_chain())
```

Ledger file:
```
agent_ledger/ledger.jsonl
```

Each line is one signed execution envelope.  
The ledger is a plain append-only JSONL file.

---

## CLI Verification

```bash
guardclaw verify agent_ledger/ledger.jsonl
```

Also works without relying on PATH:
```bash
python -m guardclaw verify agent_ledger/ledger.jsonl
```

Machine-readable output:
```bash
guardclaw verify agent_ledger/ledger.jsonl --format json
```

CI mode (exit code only):
```bash
guardclaw verify agent_ledger/ledger.jsonl --quiet
```

Verification checks:

- Chain integrity
- Signature validity
- Sequence continuity
- Schema correctness
- GEF version uniformity

---

## Envelope Structure (GEF-SPEC-1.0)

Each ledger entry contains 11 fields:

| Field | Description |
|-------|-------------|
| `gef_version` | Protocol version (`"1.0"`) |
| `record_id` | UUIDv4 |
| `record_type` | `execution`, `intent`, `result`, etc. |
| `agent_id` | Agent identifier |
| `signer_public_key` | Ed25519 public key (hex) |
| `sequence` | Monotonically increasing integer |
| `nonce` | 128-bit CSPRNG hex |
| `timestamp` | ISO-8601 UTC |
| `causal_hash` | SHA-256 of previous entry |
| `payload` | Application-defined JSON |
| `signature` | Ed25519 signature |

Signing surface excludes `signature`.

`to_chain_dict()` == `to_signing_dict()`

Both exclude `signature`.

---

## External Anchoring (Recommended)

The CLI outputs a **Chain Head Hash**:
```
SHA256(JCS(last_entry.to_chain_dict()))
```

This can be:

- Published in a Git commit
- Anchored to a transparency log
- Stored in an external system

This prevents undetectable tail truncation when the anchored head hash is externally persisted.

---

## Performance (1M Entry Benchmark)

**Environment:**

- Windows laptop
- 8GB RAM
- Python 3.13
- Single-threaded
- Strict mode (fsync enabled)
- Ed25519 signing enabled

**Results:**

| Metric | Value |
|--------|-------|
| Entries written | 1,000,000 |
| Write speed | ~762 entries/sec |
| Ledger size | ~567 MB |
| Full verify speed | ~9,213 entries/sec |
| Stream verify speed | ~2,728 entries/sec |
| Stream verify memory | ~39 MB |
| Full verify memory | ~1.3 GB |

**Notes:**

- Full verify loads all envelopes (O(N) memory)
- Stream verify is O(1) memory
- Signature verification included in verify speeds

---

## Real Use Case Example

An autonomous LLM agent executing production shell commands can emit a GuardClaw ledger.

After an incident, an auditor can:

1. Obtain the ledger file
2. Run `guardclaw verify`
3. Confirm cryptographically whether any execution entries were altered

No access to original runtime required.

---

## Security Model

**GuardClaw guarantees:**

- Tamper detection
- Reordering detection
- Mid-chain deletion detection
- Signature authenticity

**GuardClaw does NOT guarantee:**

- Protection against key compromise
- Truthfulness of payload content
- Trusted timestamps
- Distributed consensus

If the signing key is compromised, history can be rewritten.

External anchoring mitigates deletion attacks.

See `THREAT_MODEL.md`.

---

## Tests

Current suite:

- 62 adversarial tests (1 intentionally skipped)
- Tamper attacks
- Replay attacks
- Key confusion
- Crash recovery
- Canonicalization determinism

Run locally:
```bash
pytest
```

All tests should pass.

---

## Why Not X?

**Why not a database?**  
Databases can be edited without cryptographic detection.

**Why not blockchain?**  
GuardClaw is single-agent, local-first, no consensus overhead.

**Why not CloudTrail?**  
Requires trusting the provider.

**Why not append-only logs?**  
Append-only without cryptographic linkage does not provide tamper evidence.

---

## Specification

**GEF-SPEC-1.0** defines:

- Envelope schema
- Canonicalization contract
- Hash chain contract
- Signature contract
- Verification algorithm
- Security considerations

See:
[SPEC.md](SPEC.md)

---

## Design Principles

**Simplicity**  
The ledger is a plain append-only JSONL file. No databases. No proprietary formats.

**Trust Assumptions**  
Security assumes private key secrecy and the cryptographic hardness of SHA-256 and Ed25519.

**Offline Verification**  
Anyone with the public key can verify the entire ledger without access to the system that generated it.

---

## Status

- **Stable:** v0.5.2
- **Protocol:** GEF-SPEC-1.0
- **Production-ready** as a single-agent integrity layer.

---

## License

Apache License 2.0

---

## Philosophy

> Observability is not evidence.  
> Logs are not proof.  
> Integrity is measurable.
