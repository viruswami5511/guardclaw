# GuardClaw: Enterprise Cryptographic Execution Evidence & Compliance for AI Agents

[![PyPI](https://img.shields.io/pypi/v/guardclaw.svg?color=blue)](https://pypi.org/project/guardclaw/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://pypi.org/project/guardclaw/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-emerald.svg)](docs/GEF-SPEC-v1.0.md)
[![Tests](https://img.shields.io/badge/tests-274%20passing-brightgreen.svg)](#test-suite--rigor)
[![Compliance](https://img.shields.io/badge/compliance-EU%20AI%20Act%20Art.%2012%20%7C%20ISO%2042001-indigo.svg)](#regulatory-compliance-mapping)
[![Hardware](https://img.shields.io/badge/KMS-AWS%20KMS%20%7C%20Vault%20HSM-orange.svg)](#cloud-kms--hardware-isolation)

**The open-source cryptographic audit and compliance standard for autonomous AI agents.**  
GuardClaw transforms every LLM tool execution, model decision, and real-world side-effect into tamper-evident, Ed25519-signed, mathematically verifiable evidence.

---

## ⚡ The Enterprise Reality

**AI agents are executing consequential, irreversible actions: moving funds, modifying production databases, running shell commands, and accessing customer PII.**

Traditional application logs, Datadog traces, and observability dashboards are stored in mutable databases. Anyone with database admin or root access can alter or delete them. In a court of law, regulatory investigation, or SOC 2 / EU AI Act audit, **unattested logs fail legal evidentiary standards.**

GuardClaw solves this with mathematical non-repudiation:
* **RFC 8785 Canonicalization (JCS)**: Deterministic byte-level serialization across all operating systems and architectures.
* **Causal Hash DAGs**: Forward-chained $\text{SHA-256}$ linkage guaranteeing complete sequence monotonicity.
* **Out-of-Process Signing Daemon**: Zero private-key exposure inside the agent memory or sandbox.
* **Hardware Security Isolation**: FIPS 140-3 signing via AWS KMS and HashiCorp Vault HSMs.
* **RFC 6962 Merkle Inclusion Proofs**: $O(\log N)$ cryptographic existence proofs without transmitting whole ledgers.
* **Turnkey Compliance Dossiers**: Certified audit report generation for **EU AI Act Article 12** and **ISO/IEC 42001:2023**.
* **Model Context Protocol (MCP) Interceptor**: Zero-code transparent tool call auditing for Claude Desktop, Cursor, and custom agent runtimes.

---

## 🏛️ Enterprise Architecture

```
                    ZERO-KEY ISOLATED SIGNING ARCHITECTURE
┌─────────────────────────────┐                    ┌─────────────────────────────┐
│      AI AGENT RUNTIME       │                    │   GUARDCLAW SIGNING DAEMON  │
│  (Python, Node.js, MCP)     │                    │     (Isolated Container)    │
│                             │   JSON-RPC over    │                             │
│  • Triggers tool execution  │ ─────────────────► │  • Holds KMS / HSM Keys     │
│  • Calls `DaemonClient`     │   IPC / Loopback   │  • Enforces JCS & Sequences │
│  • Zero private key exposure│                    │  • Emits signed envelopes   │
└─────────────────────────────┘                    └─────────────────────────────┘
                                                                  │
                                                                  ▼
                                                   ┌─────────────────────────────┐
                                                   │   IMMUTABLE WORM STORAGE    │
                                                   │  (AWS S3 Object Lock / GCS) │
                                                   │  7-Year Legal Hold Bucket   │
                                                   └─────────────────────────────┘
```

---

## 📦 Installation

```bash
pip install --upgrade guardclaw
```

*Requires Python 3.9+. Zero external C-library compilation required.*

---

## 🚀 Quick Start: 3 Integration Models

### 1. Zero-Key Agent Client (Recommended for Production)

Run the isolated signing daemon on your host or sidecar container, allowing agents to log actions with zero local key exposure:

```bash
# Terminal 1: Start the isolated signing daemon
guardclaw daemon start --port 9443
```

```python
# Agent Process (Zero keys in memory)
from guardclaw import DaemonClient, RecordType

with DaemonClient(host="127.0.0.1", port=9443) as client:
    # Emit critical banking action
    envelope = client.emit(
        record_type=RecordType.TOOL_CALL,
        payload={
            "tool": "bank.transfer",
            "recipient": "US9128301923",
            "amount_usd": 250000.00,
            "authorized_by": "agent-core-v2",
        },
    )

print(f"Cryptographically Signed Envelope: {envelope.record_id} | Seq: {envelope.sequence}")
print(f"Causal Hash: {envelope.causal_hash}")
```

---

### 2. Standalone In-Process Ledger

For local agent scripts, notebooks, and development pipelines:

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

# 1. Initialize local key manager and ledger
key_manager = Ed25519KeyManager.generate()
ledger = GEFLedger(
    key_manager=key_manager,
    agent_id="wealth-advisor-agent",
    ledger_path="./evidence_vault",
)

# 2. Record tool invocation intent
ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={"action": "rebalance_portfolio", "target_allocation": "bonds_70_stocks_30"},
)

# 3. Verify ledger integrity mathematically
assert ledger.verify_chain() is True
```

---

### 3. Transparent Model Context Protocol (MCP) Proxy

Intercept and cryptographically sign tool calls between Claude Desktop / Cursor and upstream MCP servers with **zero code changes**:

```bash
guardclaw mcp-proxy --cmd "npx -y @modelcontextprotocol/server-filesystem ./data" --agent-id agent-fs
```

---

## 🔒 Cloud KMS & Hardware Security Isolation

GuardClaw supports native out-of-process Hardware Security Modules (HSM) so signing keys never exist in software memory:

```python
from guardclaw import GEFLedger, AWSKMSKeyProvider, RecordType

# Delegated FIPS 140-3 Level 3 signing in AWS KMS
kms_provider = AWSKMSKeyProvider(
    key_id="arn:aws:kms:us-east-1:123456789012:key/guardclaw-signing-key",
    region_name="us-east-1",
)

# Initialize ledger backed by Cloud KMS
ledger = GEFLedger(
    key_manager=kms_provider,
    agent_id="prod-trading-bot",
    ledger_path="./secure_vault",
)
```

---

## 📑 Regulatory Compliance Mapping

GuardClaw was built to directly satisfy mandatory corporate compliance requirements:

| Regulation / Standard | Mandatory Clause | How GuardClaw Satisfies the Requirement |
| :--- | :--- | :--- |
| **EU AI Act (2024/1689)** | **Article 12 (Record-Keeping)** | Continuous, automatic logging of all AI events with Ed25519 non-repudiation and RFC 8785 causal chaining. |
| **ISO/IEC 42001:2023** | **Controls A.6.2.6 & A.6.2.8** | Traceability and auditability of automated decision-making and tool invocations. |
| **SEC Rule 17a-4 / FINRA** | **WORM Storage Retention** | Direct streaming to S3 Object Lock (Compliance Mode) with immutable Legal Hold. |
| **SOC 2 Type II** | **CC6.1 & CC7.2** | Tamper-evident proof that operational audit logs have not been retroactively altered. |

### Generate a Certified Compliance Dossier via CLI:

```bash
guardclaw dossier ./evidence_vault/ledger.jsonl --output compliance_report.html --format html
```
*Produces a self-contained, audit-ready HTML executive report complete with Merkle root certificates, verification matrices, and interactive chronological event traces.*

---

## 🌳 RFC 6962 Merkle Tree Inclusion Proofs

Prove that an individual action existed in a massive multi-gigabyte ledger in $O(\log N)$ time without sharing the entire dataset:

```bash
# 1. Generate proof for a specific record ID
guardclaw prove-inclusion ./evidence_vault/ledger.jsonl --record-id gef-9a8f23... --format json > proof.json

# 2. Third-party auditor verifies the proof offline
guardclaw verify-inclusion proof.json
```

```python
from guardclaw import MerkleTree

# Build Merkle tree over ledger envelopes
tree = MerkleTree.from_ledger_file("./evidence_vault/ledger.jsonl")
print(f"Merkle Root: {tree.root_hash}")

# Extract inclusion proof for record 42
proof = tree.get_inclusion_proof(42)
assert proof.verify(expected_root=tree.root_hash) is True
```

---

## 🛠️ CLI Command Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `guardclaw verify` | Verify chain continuity, signatures, and nonces | `guardclaw verify ledger.jsonl` |
| `guardclaw export` | Export a portable `.gcbundle` evidence package | `guardclaw export ledger.jsonl -o case.gcbundle` |
| `guardclaw dossier` | Generate EU AI Act Article 12 compliance dossier | `guardclaw dossier ledger.jsonl -o report.html` |
| `guardclaw daemon` | Run the out-of-process background signing daemon | `guardclaw daemon start --port 9443` |
| `guardclaw mcp-proxy` | Universal JSON-RPC stdio tool interception proxy | `guardclaw mcp-proxy --cmd "python server.py"` |
| `guardclaw prove-inclusion` | Generate $O(\log N)$ Merkle inclusion proof | `guardclaw prove-inclusion ledger.jsonl --record-id <ID>` |
| `guardclaw verify-inclusion`| Verify an exported Merkle inclusion proof file | `guardclaw verify-inclusion proof.json` |

---

## 🧪 Test Suite & Rigor

GuardClaw is validated against a 274-test adversarial red-team suite covering:
* **Cryptographic Invariants**: Ed25519 signature mutation, padding injection, zero-key substitution.
* **Causal Graph Integrity**: Mid-chain entry deletion, sequence rollbacks, cross-session replays.
* **Multi-Process Concurrency**: High-volume parallel worker processes writing simultaneously to shared ledgers.
* **Failsafe Crash Recovery**: Incomplete write recovery, stream truncation repair, and state restoration.

```bash
pytest -v
# 274 passed in 2m 59s (100% pass rate)
```

---

## 📄 License

GuardClaw is open-source software licensed under the [Apache License, Version 2.0](LICENSE).