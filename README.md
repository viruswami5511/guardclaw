# GuardClaw

Cryptographic execution integrity for autonomous AI agents.

[![PyPI](https://img.shields.io/pypi/v/guardclaw)](https://pypi.org/project/guardclaw/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/guardclaw/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-green)](SPEC.md)
[![Tests](https://img.shields.io/badge/tests-62%20passing-brightgreen)](#tests)

---

## What Problem This Solves

AI agents are beginning to:

- execute financial transactions  
- modify production infrastructure  
- invoke tools and shell commands autonomously  
- operate without synchronous human review  

Traditional logs are mutable. Observability pipelines are not evidence.

If an AI agent makes a critical decision, how do you **prove — cryptographically** what it actually did?

GuardClaw implements **GEF-SPEC-1.0**, a language-neutral protocol for generating:

> Tamper-evident, offline-verifiable execution ledgers.

No server required. No SaaS dependency. No central verifier.  
Just a file and a public key.

---

## Core Concept

Each execution entry is:

1. Canonicalized (RFC 8785 JCS)  
2. Linked to the previous entry via SHA-256  
3. Signed using Ed25519  
4. Appended to a JSONL ledger  

Result: tamper-evident execution chain.  
Any modification, deletion, or reordering → verification fails.

---

## Install

```bash
pip install guardclaw
```

Requires Python 3.9+

Core dependencies: `cryptography`, `jcs`, `click`

---

## Quick Start

Simplest API for recording events:

```python
from guardclaw import init_global_ledger, Ed25519KeyManager
from guardclaw.api import record_action

key = Ed25519KeyManager.generate()

init_global_ledger(
    key_manager=key,
    agent_id="agent-001",
)

record_action(
    agent_id="agent-001",
    action="tool.search",
    result="success",
    metadata={"query": "AI safety"},
)
```

Ledger format: JSON Lines (one signed envelope per line).

Default output location:

```text
.guardclaw/ledger/ledger.jsonl
```

---

## 30-Second Example

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

key = Ed25519KeyManager.generate()

ledger = GEFLedger(
    key_manager=key,
    agent_id="agent-001",
    ledger_path="agent_ledger",
    mode="strict",
)

ledger.emit(
    RecordType.EXECUTION,
    payload={"action": "shell.exec", "cmd": "rm temp.txt"},
)

ledger.emit(
    RecordType.RESULT,
    payload={"status": "success"},
)

ledger.close()

print("Chain valid:", ledger.verify_chain())
```

Output:

```text
agent_ledger/ledger.jsonl
```

Each line contains one signed execution envelope.

---

## CLI Verification

Verify a ledger:

```bash
guardclaw verify agent_ledger/ledger.jsonl
```

Machine-readable output:

```bash
guardclaw verify agent_ledger/ledger.jsonl --format json
```

CI mode:

```bash
guardclaw verify agent_ledger/ledger.jsonl --quiet
```

Verification checks:

- signature validity  
- hash chain continuity  
- sequence monotonicity  
- schema correctness  
- protocol version consistency  

---

## Optional Dependencies

Install integrations:

```bash
pip install guardclaw[langchain]
pip install guardclaw[crewai]
```

---

## Integrations (v0.6.1)

GuardClaw integrates with AI systems at multiple layers.

### 🐍 LangChain Adapter

```python
from guardclaw.adapters.langchain import GuardClawCallbackHandler

handler = GuardClawCallbackHandler(agent_id="agent")

agent.run(
    "task",
    callbacks=[handler],
)
```

Records:

- tool calls  
- LLM prompts  
- completions  
- tool errors  

---

### 🤖 CrewAI Adapter

```python
from guardclaw.adapters.crewai import GuardClawCrewAdapter

adapter = GuardClawCrewAdapter("crew-agent")

crew = Crew(
    agents=[agent],
    tasks=[task],
    step_callback=adapter.record_step,
)
```

Records:

- agent steps  
- task results  
- tool errors  

---

### 🔌 MCP Proxy (Framework-Agnostic)

```python
from guardclaw.mcp import GuardClawMCPProxy

proxy = GuardClawMCPProxy("agent")

proxy.register_tool("search", search)

proxy.call("search", query="AI safety")
```

Records:

- INTENT → RESULT / FAILURE  

Works with tool-calling frameworks including:

- OpenAI  
- Anthropic Claude  
- LangChain  
- CrewAI  
- custom agents  

---

## Envelope Structure (GEF-SPEC-1.0)

| Field              | Description                    |
|--------------------|--------------------------------|
| `gef_version`      | Protocol version               |
| `record_id`        | UUIDv4                         |
| `record_type`      | `execution` / `result` / `intent` |
| `agent_id`         | Agent identifier               |
| `signer_public_key`| Ed25519 public key             |
| `sequence`         | Monotonic counter              |
| `nonce`            | CSPRNG hex                     |
| `timestamp`        | ISO-8601 UTC                   |
| `causal_hash`      | SHA-256 of previous entry      |
| `payload`          | Application JSON               |
| `signature`        | Ed25519 signature              |

Signing surface excludes the `signature` field.

---

## Integrity Model

Chain:

```text
causal_hash[N] = SHA256(JCS(entry[N-1]))
```

Genesis entry uses a zero sentinel hash.

A valid ledger requires:

- valid signatures  
- continuous sequence numbers  
- correct hash chain  
- schema validity  
- consistent protocol version  

---

## Performance (1M Entry Benchmark)

| Metric          | Value              |
|-----------------|--------------------|
| Entries written | 1,000,000          |
| Write speed     | ~760 entries/sec   |
| Ledger size     | ~567 MB            |
| Full verify     | ~9,200 entries/sec |
| Stream verify   | ~2,700 entries/sec |
| Stream memory   | ~39 MB (O(1))      |

Environment:

- Python 3.13  
- single thread  
- strict fsync  
- Ed25519 signing enabled  

---

## Security Model

GuardClaw guarantees:

- tamper detection  
- deletion detection  
- reordering detection  
- signature authenticity  

Limitations:

- key compromise allows history rewrite  
- no trusted timestamps  
- no distributed consensus  

---

## Project Structure

```text
guardclaw/
├── core/          # cryptographic protocol
├── adapters/      # framework integrations
│   ├── langchain.py
│   └── crewai.py
├── mcp/           # tool proxy
│   └── proxy.py
├── api.py         # integration API
└── cli.py         # verification CLI
```

---

## Tests

62 adversarial tests (1 skipped), covering:

- tamper attacks  
- replay attacks  
- canonicalization determinism  
- crash recovery  

Run locally:

```bash
pytest
```

---

## Specification

Protocol specification: **GEF-SPEC-1.0**

Defines:

- envelope schema  
- canonicalization contract  
- hash chain linkage  
- verification algorithm  

See:

```text
SPEC.md
```

---

## Status

Version: v0.6.1  
Protocol: GEF-SPEC-1.0  
License: Apache 2.0  

Production-ready cryptographic execution ledger for AI agents.

---

## Philosophy

> Observability is not evidence.  
> Logs are not proof.  
> Integrity is measurable.
