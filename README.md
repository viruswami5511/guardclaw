# GuardClaw

Cryptographic evidence ledger for autonomous agent accountability

Autonomous systems require stronger guarantees than mutable logs can provide.  
GuardClaw implements the minimal cryptographic properties required for replay-bound, verifiable agent evidence.  
It serves as a reference implementation of the Replay-Bound Evidence model.

GuardClaw records what AI agents do and makes those records cryptographically verifiable.

It does not block execution.  
It does not enforce policy.  
It does not require SaaS infrastructure.  

It provides verifiable evidence of what was recorded.

📄 Formal protocol specification: [docs/PROTOCOL.md](docs/PROTOCOL.md)

---

## Status

Alpha (v0.1.1)

GuardClaw v0.1.1 is experimental software.  
Breaking changes may occur before v1.0.

Appropriate for development, research, and low-risk automation.  
Not recommended for high-risk production systems.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) for explicit guarantees and limitations.

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

GuardClaw is an evidence layer, not a control plane.

---  

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) for full analysis.

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

Planned future areas:

- Hash chaining  
- Durable replay protection  
- Key rotation audit events  
- External timestamp anchoring  
- Delegated authority model  

These are not part of v0.1.1 guarantees.

---

## When to Use GuardClaw (v0.1.1)

*Appropriate for:*

- Development environments  
- Internal AI tooling  
- Research prototypes  
- Low-risk automation  
- Audit experimentation  

*Not recommended for production use in:*

- Financial settlement systems  
- Critical infrastructure  
- Regulatory-grade audit without additional controls  
- Long-term archival systems  
- High-risk autonomous systems  

---

## Contributing

Contributions are welcome.

Before submitting:

- Read [PROTOCOL.md](docs/PROTOCOL.md)  
- Read [SECURITY.md](SECURITY.md)  
- Include tests  
- Avoid expanding guarantees beyond documented scope  

---

## License

Apache-2.0

---

## Philosophy

GuardClaw does not promise perfect safety.

It provides cryptographic evidence of what was recorded.

Nothing more. Nothing less.
