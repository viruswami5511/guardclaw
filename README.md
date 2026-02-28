See this created in earlier chat-

# GuardClaw

**Cryptographic accountability protocol for autonomous AI agents.**

#Guardclaw


[![PyPI](https://img.shields.io/pypi/v/guardclaw)](https://pypi.org/project/guardclaw)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-green)](SPEC.md)
[![Tests](https://img.shields.io/badge/tests-45%2F45%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/guardclaw)


GuardClaw implements the **GuardClaw Execution Framework (GEF)** — a language-neutral cryptographic protocol for tamper-evident AI agent audit trails.

As AI agents begin executing financial transactions, accessing production systems, and acting autonomously, conventional logging is insufficient for audit, dispute resolution, and regulatory non-repudiation.

Every agent action is **Ed25519-signed**, **SHA-256 hash-chained**, and **RFC 8785 canonicalized**. Any post-signing modification to any field
of any entry breaks verification. Any third party with the public key can verify offline — no central server, no SaaS trust required.

---

## Try It in 3 Commands

```bash
pip install guardclaw
git clone https://github.com/viruswami5511/guardclaw-demo
cd guardclaw-demo && python run_demo.py
```

[Full demo with tamper simulation →](https://github.com/viruswami5511/guardclaw-demo)

[Run this demo yourself →](https://github.com/viruswami5511/guardclaw-demo)

---

## What GuardClaw Provides

- **Ed25519 per-envelope signing** — RFC 8032 pure Ed25519
- **SHA-256 causal hash chaining** — every entry cryptographically bound to its predecessor
- **RFC 8785 JCS canonical serialization** — byte-identical across Python, Go, any language
- **Active nonce uniqueness enforcement** — duplicate replay detected (INV-29)
- **Sequence gap detection** — deleted or reordered entries detected
- **Offline verifiability** — ledger file + public key is sufficient
- **33 formally defined protocol invariants** — 45/45 tests passing
- **Cross-language proof** — Python and Go produce byte-identical chain hashes and interverifiable signatures

## What GuardClaw Does NOT Provide

- Policy enforcement or authorization control
- Distributed consensus
- Tail truncation detection without external anchoring (Level 4)
- Trusted timestamp authority (RFC 3161 — future)
- Key compromise detection
- Cross-ledger replay prevention

> GuardClaw is an evidence layer, not a control plane.
> It proves what was recorded. It does not prevent actions.

---

## Status

**Stable — v0.5.1** | **Protocol: GEF-SPEC-1.0**

Appropriate for:
- Development and internal AI agent audit trails
- Research prototypes and compliance evaluation
- Any system requiring offline-verifiable cryptographic evidence

The reference implementation is production-stable and covered by invariant tests and cross-language proof artifacts.

For financial settlement, critical infrastructure, or regulatory-grade deployments: evaluate key management and Level 4 anchoring requirements
against your threat model. See THREAT_MODEL.md.

---

## Installation

```bash
pip install guardclaw
```

Requires Python 3.9+. Core dependencies: `cryptography>=41.0.0`, `jcs>=0.2.0`.

---

## Quick Start

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

# Generate a signing key
key = Ed25519KeyManager.generate()
key.save("agent_key.json")

# Create a ledger (ledger_path is a directory)
ledger = GEFLedger(
    key_manager=key,
    agent_id="agent-prod-001",
    ledger_path="agent_ledger"
)

# Record agent actions
ledger.emit(
    record_type=RecordType.INTENT,
    payload={"instruction": "analyze quarterly report"}
)

ledger.emit(
    record_type=RecordType.EXECUTION,
    payload={"action": "file.read", "target": "q4_report.pdf"}
)

ledger.emit(
    record_type=RecordType.RESULT,
    payload={"status": "success", "summary": "Analysis complete"}
)

# Check chain integrity
print(ledger.verify_chain())  # True
print(ledger.get_stats())
```

Each envelope is automatically:
- Assigned a cryptographically random 32-character hex nonce
- SHA-256 hash-chained to its predecessor
- Ed25519-signed before the call returns

The ledger is written to `agent_ledger/ledger.jsonl`.

---

## Verifying a Ledger

```python
from guardclaw.core.replay import ReplayEngine

engine = ReplayEngine(silent=True)
engine.load("agent_ledger/ledger.jsonl")
summary = engine.verify()

print(f"Entries:    {summary.total_entries}")
print(f"Violations: {len(summary.violations)}")
print(f"Chain:      {'VALID' if summary.chain_valid else 'BROKEN'}")
```

Or via CLI:

```bash
guardclaw verify agent_ledger/ledger.jsonl
```

Verification requires only:
- The ledger `.jsonl` file
- The signer's public key (embedded in every envelope)

No network access. No shared secrets. No trust in the producing system.

---

## Demo: Tamper Detection in Action

```
python run_demo.py
→  intent        nonce=3f8a2b1d4e...  chain=...4a2f1c8e
→  execution     nonce=9c1e5d2f7a...  chain=...b7e39210
→  execution     nonce=1a7f3e8b2c...  chain=...c4d891b3
→  execution     nonce=5b2d9c1f4e...  chain=...8f2a1e4d
→  result        nonce=7e1c4f8a2b...  chain=...2e7b4f1a
→ Ledger written: demo_ledger.jsonl

python verify.py
→ RESULT: CLEAN — 0 violations

python tamper.py
→ Entry #2 payload modified (endpoint + result changed)

python verify.py
→ RESULT: TAMPERED
→ [seq 2] INVALID_SIGNATURE
→ [seq 3] CHAIN_BREAK
→ 2 violations detected
```

Run this demo yourself →

---

## The GEF Envelope

Every entry in the ledger is a signed JSON envelope with 11 fields:

| Field | Type | Description |
|---|---|---|
| `gef_version` | string | Protocol version (`"1.0"`) |
| `record_id` | string | UUID v4, unique per entry |
| `record_type` | string | `execution`, `intent`, `result`, `failure` |
| `agent_id` | string | Identifier of the acting agent |
| `signer_public_key` | string | Ed25519 public key (64 lowercase hex chars) |
| `sequence` | integer | Zero-based monotonically increasing integer |
| `nonce` | string | 128-bit CSPRNG hex string (32 chars) |
| `timestamp` | string | ISO 8601 UTC with millisecond precision |
| `causal_hash` | string | SHA-256 of previous entry's signing surface |
| `payload` | object | Application-defined JSON object |
| `signature` | string | Ed25519 over JCS canonical bytes (excluded from signing surface) |

The signing surface is the 10-field object excluding `signature`.
Chain and signature integrity are independently verifiable.

Full specification: SPEC.md

---

## Three Protocol Contracts

**Contract I — RFC 8785 JCS**
Every signing surface is canonicalized using RFC 8785 JCS. Identical inputs produce byte-identical output on any conformant RFC 8785 implementation.

**Contract II — SHA-256 Causal Chain**
```
causal_hash[N] = hex(SHA-256(JCS(signing_surface[N-1])))
```
The genesis entry uses 64 zero characters as the sentinel value. Any modification to any entry breaks the chain from that point forward.

**Contract III — Ed25519 Authenticity**
Every envelope is signed with pure Ed25519 (RFC 8032 §5.1). `signer_public_key` is embedded in the signing surface — no external PKI required for verification.

---

## Cross-Language Proof

The `cross_lang_proof/` directory contains a publicly reproducible proof that the Python reference implementation and an independent Go implementation produce:

- Byte-identical JCS canonical bytes
- Byte-identical SHA-256 chain hashes
- Ed25519 signatures from Python that verify correctly in Go
- Single-byte mutation breaks verification in both

```
cross_lang_proof/
├── emit_proof.py       ← Python: generate proof bundle
├── verify_proof.go     ← Go: verify byte-identical output
├── proof_bundle.json   ← The proof artifact
└── run_proof.ps1       ← One-command runner (Windows)
```

The proof bundle includes canonical bytes, SHA-256 hashes, and signatures for fully reproducible independent verification.

See SPEC.md Section 12.3 for the full verified implementations table.

---

## Conceptual Foundation

GuardClaw v0.5.1 implements **Level 3 (Chained Integrity)** of the Evidence Maturity Model defined in the Replay-Bound Evidence whitepaper.

| Level | Name | GuardClaw |
|---|---|---|
| 2 | Replay-Bound Evidence — signed + replay-protected | ✅ v0.1.x+ |
| 3 | Chained Integrity — + SHA-256 hash chain, gap detection | ✅ v0.5.1 |
| 4 | Anchored Provenance — + RFC 3161 timestamping | Planned |

The Evidence Maturity Model is defined in the whitepaper above. It is not part of the GEF protocol specification.

**Whitepaper:** Replay-Bound Evidence: Cryptographic Accountability for Autonomous AI Systems
**DOI:** 10.5281/zenodo.18712808 | Published: 2026-02-20 | CC-BY 4.0

The whitepaper defines the **"why"**.
GEF-SPEC-1.0 defines the **"how"**.

---

## Protocol Specification

SPEC.md — GEF-SPEC-1.0, the complete normative specification.

Covers:
- 11-field envelope schema and encoding rules
- Three protocol contracts (JCS, SHA-256, Ed25519)
- 33 formal invariants
- Full verification procedure
- Security considerations and threat model
- Versioning and forward compatibility
- Non-normative design rationale

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/test_gef_invariants.py -v
```

Expected: **45 passed** — all 33 GEF-SPEC-1.0 invariants covered.

Test classes:
- `TestSigningInvariants` — INV-01 to INV-08
- `TestChainInvariants` — INV-09 to INV-14
- `TestSchemaInvariants` — INV-15 to INV-22
- `TestReplayInvariants` — INV-23 to INV-28
- `TestNonceInvariants` — INV-29 to INV-30
- `TestCrossLanguageInvariants` — INV-31 to INV-33

---

## Security

- SECURITY.md — supported versions, vulnerability reporting, cryptographic primitives
- THREAT_MODEL.md — threat classification by scenario
- SPEC.md Section 11 — full security considerations and known limitations

To report a vulnerability privately: GitHub Security Advisories

---

## Contributing

See CONTRIBUTING.md.

To implement GEF in another language, see SPEC.md Section 12 for
compliance requirements and test vectors.

To register a verified implementation, open a proposal with evidence of
test vector compliance and all 33 invariants passing.

---

## Repository Structure

```
guardclaw/
├── guardclaw/              ← Python package
│   └── core/
│       ├── models.py       ← ExecutionEnvelope, RecordType
│       ├── replay.py       ← ReplayEngine (two-phase verification)
│       ├── crypto.py       ← Ed25519KeyManager
│       └── canonical.py    ← RFC 8785 JCS canonicalization
├── tests/
│   └── test_gef_invariants.py  ← 45 invariant tests
├── cross_lang_proof/       ← Python + Go cross-language proof
├── docs/
│   └── replay-bound-evidence-v1.0.md  ← Conceptual whitepaper (DOI)
├── SPEC.md                 ← GEF-SPEC-1.0 (authoritative protocol spec)
├── THREAT_MODEL.md         ← Threat classification
├── SECURITY.md             ← Security policy
└── CONTRIBUTING.md         ← Contribution guide
```

---

## License

Apache License 2.0 — see LICENSE.

---

## Philosophy

> Observability is not evidence.
> Logging is not proof.
> Trust is not verification.

GuardClaw provides cryptographic evidence of what was recorded.
Nothing more. Nothing less.