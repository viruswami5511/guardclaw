# GuardClaw

**Cryptographic execution integrity for autonomous AI agents.**

[![PyPI](https://img.shields.io/pypi/v/guardclaw)](https://pypi.org/project/guardclaw/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/guardclaw/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-green)](docs/GEF-SPEC-v1.0.md)
[![Tests](https://img.shields.io/badge/tests-117%20passing-brightgreen)](#tests)

---

**AI agents are executing real actions. Deleting files. Moving money. Calling APIs.**  
**And you have no cryptographic proof of what they actually did.**

Logs lie. Observability is not evidence. If something goes wrong — and it will —  
you need to prove what happened. Not guess. Not hope. **Prove.**

GuardClaw turns every agent action into tamper‑evident, cryptographically signed,  
offline‑verifiable evidence. No server. No SaaS. No trust required.

**AI agents without cryptographic execution evidence will not meet future regulatory and security expectations.**

---

## The Problem

Traditional logging assumes good faith. Anyone with write access can modify a log.  
Observability pipelines are not legally or forensically robust. They were never designed to be.

**AI agents are now executing consequential, often irreversible actions:**

- Financial transactions  
- Infrastructure modifications  
- Shell commands and file operations  
- API calls with real‑world side effects  

If an agent misbehaves, gets compromised, or is falsely accused —  
can you prove what it actually did? With current tooling: **no.**

---

## The Solution

GuardClaw implements **GEF‑SPEC‑1.0**, a cryptographic execution ledger protocol  
that makes every agent action **provable, not just observable.**

```text
Each action → canonicalized → SHA‑256 chained → Ed25519 signed → appended.
No step is optional. Every entry is independently verifiable and globally consistent.
```

Break the chain. Flip one byte. Reorder one entry.  
**Verification fails — immediately, deterministically, without ambiguity.**

---

## Who This Is For

- Teams deploying autonomous or semi-autonomous AI agents  
- Security engineers who need provable execution trails  
- Infra / platform teams building agent platforms  
- Auditors and compliance teams evaluating AI system behavior

---

## Core Guarantees

| What GuardClaw guarantees        | What that means in practice                        |
|----------------------------------|----------------------------------------------------|
| 🔐 Tamper detection              | Any modification to any entry is detectable        |
| 🔁 Order integrity               | Reordering entries breaks verification             |
| ❌ Deletion detection            | Missing entries invalidate the entire chain        |
| ✍️ Signature authenticity        | Every entry is Ed25519‑signed by the agent        |
| 📦 Portable evidence             | Export as a self‑contained `.gcbundle` for audits |

**Honest limitations:**

- Key compromise allows history rewrite  
- No trusted timestamping (e.g. RFC 3161)  
- No distributed consensus  

GuardClaw is the **evidence layer**, not a blockchain, not a key vault, not a policy engine.

---

## Install

```bash
pip install guardclaw
```

Requires **Python 3.9+**. Core dependencies: `cryptography`, `jcs`, `click`.

---

## Quick Start

```python
from guardclaw import GEFLedger, Ed25519KeyManager

key = Ed25519KeyManager.generate()

ledger = GEFLedger(
    key_manager=key,
    agent_id="agent-001",
    ledger_path="agent_ledger",
    mode="strict",
)

ledger.emit(
    record_type="execution",
    payload={"action": "shell.exec", "cmd": "rm temp.txt"},
)

ledger.emit(
    record_type="result",
    payload={"status": "success"},
)

result = ledger.verify_chain()
print("Chain valid:", result)
```

Output (ledger on disk):

```text
agent_ledger/ledger.jsonl   # JSONL format, one signed envelope per line
```

One JSONL ledger file. One public key.  
No network calls. No trusted server. No hidden state.

---

## How It Works

Each execution entry is:

1. **Canonicalized** using RFC 8785 JCS — deterministic, byte‑for‑byte reproducible  
2. **Hash‑chained** — each entry commits to the full history before it  
3. **Ed25519 signed** — cryptographically bound to the agent’s identity  
4. **Appended** to a JSONL ledger file (`ledger.jsonl`), the on-disk representation of the GEF ledger 

**Chain linkage:**

```text
causal_hash[N] = SHA256( JCS( entry[N-1] ) )
```

The genesis entry uses a zero sentinel hash.  
Any modification, deletion, or reordering → verification fails.

### Envelope Structure (GEF‑SPEC‑1.0)

| Field              | Description                                      |
|--------------------|--------------------------------------------------|
| `gef_version`      | Protocol version                                 |
| `record_id`        | UUIDv4 — globally unique entry identifier        |
| `record_type`      | `genesis` / `execution` / `result` / `intent`    |
| `agent_id`         | Agent identifier                                 |
| `signer_public_key`| Ed25519 public key (base64url)                   |
| `sequence`         | Monotonic counter — gaps are tamper signals      |
| `nonce`            | CSPRNG hex; presence supports replay resistance  |
| `timestamp`        | ISO‑8601 UTC                                     |
| `causal_hash`      | SHA‑256 of previous entry (JCS‑canonicalized)    |
| `payload`          | Application JSON payload                         |
| `signature`        | Ed25519 over the signing surface (excludes this) |

---

## Verification

GuardClaw stores the on-disk ledger as newline-delimited JSON (`ledger.jsonl`), while `.gef` refers to the GuardClaw Evidence Format and is used for protocol/bundle identity. GuardClaw accepts both `.jsonl` and `.gef` ledger filenames; the format is content-based. In this README, `ledger.jsonl` is used for the on-disk raw ledger for clarity, while `.gef` is used for protocol and bundle identity.

```bash	
# Verify a ledger
guardclaw verify agent_ledger/ledger.jsonl

# Verify a bundle (verifies contained ledger)
guardclaw verify case.gcbundle

# JSON output for CI/automation
guardclaw verify agent_ledger/ledger.jsonl --format json

# Exit‑code‑only mode (CI pipelines)
guardclaw verify agent_ledger/ledger.jsonl --quiet

# Export full audit report
guardclaw verify agent_ledger/ledger.jsonl --format json > report.json
```

Verification checks on every entry:

- Ed25519 signature validity  
- Hash chain continuity (`causal_hash` linkage)  
- Sequence monotonicity (gap detection)  
- Schema correctness  
- Protocol version consistency  
- Nonce presence / basic replay resistance  

Exit codes: `0` = valid, `1` = invalid, `2` = error.

---

## Evidence Bundles

When you need to share proof with an auditor, regulator, or third party — export a bundle:

```bash
guardclaw export agent_ledger/ledger.jsonl
guardclaw export audit.jsonl --output case.gcbundle
guardclaw export audit.jsonl --output ./evidence --format json
```

**Bundle layout:**

```text
case.gcbundle/
├── ledger.gef          ← Primary cryptographic trust anchor
├── manifest.json       ← Bundle identity + ledger stats
├── verification.json   ← Verification snapshot (informational only)
├── public_key.json     ← Ed25519 key extracted FROM the ledger
├── summary.json        ← Replay summary
└── report.html         ← Self‑contained human‑readable evidence report
```

**Trust model — non‑negotiable:**

- `ledger.gef` is the **primary cryptographic trust anchor.** All other files are derived.  
- `verification.json` is **informational only.** Consumers should re‑verify `ledger.gef` themselves.  
- `public_key.json` is extracted from `signer_public_key` inside the ledger —  
  never generated independently — preventing identity substitution attacks.

Export is refused if the ledger is invalid.  
Ledgers with multiple signing identities are rejected during export validation.

---

## Integrations

### LangChain

```python
from guardclaw.adapters.langchain import GuardClawCallbackHandler

handler = GuardClawCallbackHandler(agent_id="agent")
agent.run("task", callbacks=[handler])
```

Records: tool calls, LLM prompts, completions, tool errors.

---

### CrewAI

```python
from guardclaw.adapters.crewai import GuardClawCrewAdapter

adapter = GuardClawCrewAdapter("crew-agent")
crew = Crew(agents=[agent], tasks=[task], step_callback=adapter.record_step)
```

Records: agent steps, task results, tool errors.

---

### MCP Proxy (Framework‑Agnostic)

```python
from guardclaw.mcp import GuardClawMCPProxy

proxy = GuardClawMCPProxy("agent")
proxy.register_tool("search", search)
proxy.call("search", query="AI safety")
```

Records `INTENT → RESULT / FAILURE` pairs.  
Works with OpenAI, Anthropic, LangChain, CrewAI, and custom agents.

---

## Performance

Benchmarked at 1M entries — local machine, single‑threaded, strict durability (fsync) enabled, Ed25519 signing on: 

| Metric                | Value                |
|-----------------------|----------------------|
| Entries written       | 1,000,000            |
| Write speed           | ~760 entries/sec     |
| Ledger size           | ~567 MB              |
| Full verify speed     | ~9,200 entries/sec   |
| Stream verify speed   | ~2,700 entries/sec   |
| Stream verify memory  | ~39 MB — O(1)        |

---

## Compliance & Audit Readiness

GuardClaw is not a “compliance product” by itself, but it **provides the cryptographic
evidence layer** that modern regulations and auditors increasingly expect.

When combined with correct data handling, key management, and governance, GuardClaw’s
ledgers and evidence bundles can support:

- Financial and operational audits (e.g. SOX‑style internal controls)
- EU‑style regulatory investigations (GDPR/DORA/AI‑Act contexts)
- India/RBI‑aligned IT and incident forensics expectations
- Internal risk, security, and model‑governance reviews

GuardClaw does one thing extremely well: it gives you a tamper‑evident, independently
verifiable record of what your AI agents actually did. That record can be plugged into
whatever regulatory or compliance regime you operate under.

---

## Tests

**118 passed, 1 skipped.** Adversarial scenarios covered:

- Payload, signature, and hash tampering  
- Replay attacks  
- Chain corruption (sequence gaps, causal hash mismatch)  
- Identity mismatch (multiple signing keys)  
- Canonicalization determinism  
- Crash recovery and strict vs recovery modes  

```bash
pytest
```

---

## Specification

**GEF-SPEC-v1.0** — Stable. Implemented in GuardClaw v0.7.x.

Defines the complete contract for:

- Envelope schema and field semantics
- RFC 8785 JCS canonicalization
- SHA-256 hash chain linkage rules
- Ed25519 signing surface
- Verification algorithm, failure types, and exit codes

See [`docs/GEF-SPEC-v1.0.md`](docs/GEF-SPEC-v1.0.md).

**GEF-SPEC-v1.1-draft** — Experimental roadmap. Not yet implemented.  
Covers subject-scoped nonces, multi-ledger identity, content commitment,
key rotation, and tail anchoring.

See [`docs/GEF-SPEC-v1.1-draft.md`](docs/GEF-SPEC-v1.1-draft.md).

---

## Project Structure

```text
guardclaw/
├── core/           # GEF‑SPEC‑1.0 protocol implementation
├── bundle/         # Evidence bundle export (.gcbundle)
│   ├── exporter.py
│   ├── models.py from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
│   └── report.py
├── adapters/       # Framework integrations
│   ├── langchain.py
│   └── crewai.py
├── mcp/            # Tool proxy (framework‑agnostic)
├── cli/            # verify + export commands
├── api.py          # GEFSession, record_action, verify_ledger
└── trace.py        # @trace decorator
```

---

## Status

| Property        | Value        |
|-----------------|--------------|
| Version         | v0.7.1       |
| Protocol        | GEF‑SPEC‑1.0 |
| License         | Apache 2.0   |
| Ledger protocol | Stable       |
| Bundle system   | Stable (v1)  |

---

## Philosophy

The AI industry has built extraordinary capabilities with essentially zero  
accountability infrastructure. Agents act. Logs are written. Nobody can prove anything.

> Observability is not evidence.  
> Logs are narratives. Evidence is math.  
> GuardClaw turns AI execution into cryptographic truth.