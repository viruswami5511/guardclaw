\# Security Policy



\*\*Status:\*\* Stable  

\*\*Version:\*\* v0.5.1  

\*\*Protocol:\*\* GEF-SPEC-1.0



---



\## Supported Versions



| Version | Status |

|---|---|

| 0.5.x | ✅ Supported — current stable |

| 0.2.x | ⚠️ Deprecated — upgrade to 0.5.x |

| 0.1.x | ❌ Unsupported — no GEF protocol |



---



\## Reporting a Vulnerability



\*\*Report via:\*\* GitHub Security Advisories https://github.com/viruswami5511/guardclaw/security/advisories

\*\*Response target:\*\* 72 hours  

\*\*Disclosure policy:\*\* Coordinated disclosure preferred



Please include:



\- Affected version

\- Description of the vulnerability

\- Whether it affects the GEF protocol design, the Python

&nbsp; implementation, or both

\- Proof of concept if available



---



\## Cryptographic Primitives



GuardClaw v0.5.1 uses:



| Primitive | Algorithm | Reference |

|---|---|---|

| Signatures | Ed25519 (pure) | RFC 8032 §5.1 |

| Chain hashing | SHA-256 | FIPS 180-4 |

| Canonicalization | JCS | RFC 8785 |

| Encoding | Base64url (no padding) | RFC 4648 §5 |

| Nonce | 128-bit CSPRNG | OS-provided |



Ed25519ph and Ed25519ctx (RFC 8032 §5.2, §5.3) are explicitly

excluded. Only pure Ed25519 is used.



Vulnerabilities in these primitives are outside project scope.

A new `gef\_version` with updated primitives would be required

per SPEC.md Section 14.



---



\## Protocol Security Scope



GuardClaw's cryptographic guarantees are defined in:



\- \*\*SPEC.md Section 11\*\* — Security Considerations

\- \*\*SPEC.md Section 10\*\* — 33 Formal Invariants

\- \*\*THREAT\_MODEL.md\*\* — Threat classification by scenario



Known limitations (by design):



\- Tail truncation is not detectable without external anchoring

\- Timestamps are operator-asserted (not RFC 3161 anchored)

\- Cross-ledger replay is out of scope in GEF v1.0

\- Key compromise allows new valid records but not retroactive

&nbsp; modification of existing records



---



\## Suitable Deployment Contexts



| Context | Suitable |

|---|---|

| Development and testing | ✅ |

| Internal AI agent audit trails | ✅ |

| Research and prototyping | ✅ |

| Compliance-grade audit (Level 3) | ✅ with appropriate key management |

| Regulatory-grade with timestamp proof | ⚠️ Requires Level 4 (RFC 3161 anchoring — future) |

| Financial settlement, critical infrastructure | ⚠️ Evaluate key management and anchoring requirements |



---



\## Disclosure



GuardClaw v0.5.1 implements GEF-SPEC-1.0 — a stable, formally specified cryptographic accountability protocol. It is a foundational accountability layer, not a complete security system. Use additional controls where your threat model requires them.



