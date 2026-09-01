# GuardClaw: The Open Cryptographic Execution Format for AI Agents

[![PyPI](https://img.shields.io/pypi/v/guardclaw.svg?color=blue)](https://pypi.org/project/guardclaw/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://pypi.org/project/guardclaw/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-GEF--SPEC--1.0-emerald.svg)](docs/GEF-SPEC-v1.0.md)

GuardClaw implements **GEF-SPEC-1.0** — a vendor-neutral, language-agnostic protocol for turning AI agent tool calls into tamper-evident, offline-verifiable execution records.

No server required. No SaaS dependency. No central verifier. Just a signed file and a public key.

---

## Why this exists

AI agents now run shell commands, call APIs, and modify production systems. Standard application logs live in mutable databases — anyone with admin or root access can alter them after the fact. GEF-SPEC gives you a different guarantee: a hash-chained, Ed25519-signed ledger where any tampering breaks the chain and is mathematically detectable.

**This is honest about its scope.** GuardClaw proves what was recorded — not whether the action was wise, authorized, or safe. It's an evidence layer, not a policy engine.

---

## What it actually does today

- **RFC 8785 canonicalization (JCS)** — deterministic serialization across platforms.
- **Causal hash chains** — SHA-256 forward-linked envelopes; any gap or reorder is detectable.
- **Ed25519 signing**, with an optional out-of-process signing daemon so keys never live in agent memory.
- **AWS KMS / HashiCorp Vault support** for delegated signing (KMS HSMs are FIPS 140-2 Level 3 validated in most regions — verify current validation status for your specific region/key type before relying on this for a compliance claim).
- **RFC 6962 Merkle inclusion proofs** — prove a single record existed in a large ledger without sharing the whole file.
- **MCP proxy mode** — intercept and sign tool calls between an MCP client and server with no code changes.
- **274-case internal adversarial test suite** covering signature mutation, chain tampering, and crash recovery. This is our own test suite, not a third-party audit — treat it as evidence of engineering rigor, not as independent certification.

---

## What it doesn't do (yet)

- No independent security audit or penetration test has been performed.
- No production deployments at scale are known to us.
- Compliance mapping (EU AI Act, SOC 2, etc.) describes how the primitives *could* support those requirements — it is not a certification, legal opinion, or guarantee of audit acceptance. Talk to your own counsel and auditors.

---

## Quick start

```bash
pip install --upgrade guardclaw
```

```python
from guardclaw import GEFLedger, Ed25519KeyManager, RecordType

key_manager = Ed25519KeyManager.generate()
ledger = GEFLedger(
    key_manager=key_manager,
    agent_id="my-agent",
    ledger_path="./evidence_vault",
)

ledger.emit(
    record_type=RecordType.TOOL_CALL,
    payload={"action": "example_action", "detail": "..."},
)

assert ledger.verify_chain() is True
```

---

## Out-of-Process Signing Daemon (Zero Key Exposure)

For production deployments where agent processes should not hold private signing keys in memory:

```bash
# Start background daemon
guardclaw daemon start --port 9443
```

```python
from guardclaw import DaemonClient, RecordType

with DaemonClient(host="127.0.0.1", port=9443) as client:
    env = client.emit(
        record_type=RecordType.TOOL_CALL,
        payload={"action": "rebalance_portfolio", "amount": 1000},
    )
```

---

## Model Context Protocol (MCP) Transparent Proxy

Intercept and sign tool calls between Claude Desktop / Cursor and upstream MCP servers with zero code modifications:

```bash
guardclaw mcp-proxy --cmd "npx -y @modelcontextprotocol/server-filesystem ./data"
```

---

## Where this fits

Provenance standards like **SLSA** and **in-toto** attest to how software was *built and deployed* — a point-in-time, pre-execution guarantee.

**GuardClaw addresses a different moment in the lifecycle:** what an autonomous agent *does at runtime*, as it executes tool calls and interacts with external systems.

We are one of several independent groups exploring runtime execution attestation for AI agents in 2026. What we offer today is:
1. **A Python reference implementation** for Python agent runtimes and frameworks.
2. **A zero-code MCP stdio proxy** that wraps and signs tool invocations for any server speaking the Model Context Protocol (regardless of whether the server was written in TypeScript, Python, or Go).
3. **An open, vendor-neutral envelope format (`GEF-SPEC-1.0`)** based on RFC 8785 canonicalization and Ed25519 signatures.

If you maintain an MCP tool or Python agent framework and want to experiment with runtime cryptographic evidence, we welcome issues and pull requests.

---

## License

Apache 2.0. Fork it, extend it, integrate it — the code was never the moat.