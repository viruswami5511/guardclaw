\# Replay-Bound Evidence

\## Cryptographic Accountability for Autonomous AI Systems



\*\*Version:\*\* 1.0 (Public Discussion Draft)  

\*\*Author:\*\* GuardClaw Project



---



\## Abstract



When autonomous AI systems cause financial loss, violate policy, or make consequential decisions, traditional logs often cannot answer a fundamental question:



> Can you prove what happened?



Database records may be altered. Timestamps may be manipulated. Events may be duplicated or replayed. Audit trails frequently depend on operator trust.



This paper defines \*\*Replay-Bound Evidence\*\* — a minimal framework for producing cryptographically verifiable records of AI agent actions.



Replay-Bound Evidence provides:

\- Tamper-evident event history

\- Per-subject replay protection

\- Canonical serialization

\- Offline verifiability



It does not enforce policy.  

It does not guarantee correctness.  

It does not prevent malicious action.



Replay-Bound Evidence can be understood as a \*\*flight recorder for autonomous systems\*\*: passive, tamper-evident, and activated primarily when things go wrong.



A reference implementation exists as the \*\*GuardClaw open-source project (v0.1.x)\*\*.



This document defines properties, not a product. It establishes the minimal requirements for cryptographically verifiable AI accountability.



---



\## 1. The Problem: Autonomous Action Without Verifiable Proof



AI agents are increasingly:

\- Executing financial trades

\- Modifying infrastructure

\- Making access control decisions

\- Triggering operational workflows

\- Acting across interconnected systems



As autonomy increases, independent verification becomes more complex.



When incidents occur, organizations must answer:

\- Who authorized this?

\- What exactly was executed?

\- Was this duplicated?

\- Was this tampered with?

\- Can a third party verify this independently?



Traditional logging systems were designed for observability and debugging — not adversarial verification.



This creates the \*\*Evidence Gap\*\*:



> Systems can record events, but cannot prove those records are authentic, unique, and untampered.



\*\*Logging answers:\*\*  

\*"What happened according to the system?"\*



\*\*Evidence must answer:\*\*  

\*"Can this record be independently verified?"\*



---



\## 2. Illustrative Scenario



\### Financial Trading Agent



An AI trading agent executes 1,200 trades per day.



Six months later:

\- A regulator requests proof that risk limits were respected on May 15.

\- A client alleges duplicate trades.

\- Internal audit questions whether logs were modified post-incident.



\### Traditional Logging



The organization provides:

\- Database entries

\- Cloud logs

\- Monitoring dashboards



These logs:

\- May be editable by administrators

\- Depend on infrastructure trust

\- Do not inherently prevent replay

\- Cannot be independently verified offline



Verification depends on trusting the operator.



\### Replay-Bound Evidence



Instead, the organization provides:

\- Cryptographically signed event records

\- Subject-scoped replay protection

\- Canonical serialization

\- A public verification key



A third party can independently verify:

\- The record has not been modified

\- No duplicate event exists within subject scope

\- The signature corresponds to the issuing authority

\- Ledger-local ordering integrity



This distinction materially affects governance, legal defensibility, and trust boundaries.



---



\## 3. Defining Replay-Bound Evidence



Replay-Bound Evidence refers to:



> Non-reusable, cryptographically attested event records within a defined subject scope.



"Replay-Bound" indicates that a valid signed event cannot be reused or duplicated undetected within its domain.



A system produces Replay-Bound Evidence if it satisfies four minimal properties.



---



\### 3.1 Attested Events



Each recorded event \*\*MUST\*\* be cryptographically signed.



This provides:

\- \*\*Integrity\*\* — modification invalidates the signature

\- \*\*Attribution\*\* — event bound to signing identity

\- \*\*Non-repudiation\*\* — within limits of key security



Without attestation, logs remain mutable records.



---



\### 3.2 Replay Protection (Subject-Scoped)



Each event \*\*MUST\*\* be uniquely constrained within its subject scope.



This may be implemented via:

\- A per-subject nonce (unique identifier), or

\- A strictly increasing per-subject sequence number



\#### Formal Invariant (Nonce-Based Implementation)



For subject S, event Eᵢ is valid if and only if:



1\. `VerifySignature(Eᵢ)` is true under S's public key

2\. `Nonce(Eᵢ)` has not previously appeared within S's ledger domain



If either condition fails, the event is invalid.



This invariant defines the replay-bound property.



Sequence-based implementations may alternatively enforce:

```

Sequence(Eᵢ) = Sequence(Eᵢ₋₁) + 1

```



Either mechanism satisfies replay-boundedness, provided uniqueness within subject scope is enforced deterministically.



---



\### 3.3 Canonical Serialization



Events \*\*MUST\*\* be serialized deterministically prior to signing.



Without canonicalization:

\- Equivalent data may hash differently

\- Signature verification becomes ambiguous

\- Cross-system verification may fail



Canonical encoding ensures:



> Identical semantic inputs produce identical cryptographic representations.



---



\### 3.4 Offline Verifiability



Verification \*\*MUST NOT\*\* depend on the originating infrastructure.



A third party \*\*MUST\*\* be able to verify:

\- Signature validity

\- Replay uniqueness within ledger scope

\- Structural correctness



Using only:

\- The event record

\- The public key

\- Deterministic verification logic



If verification requires live infrastructure access, accountability is weakened.



---



\## 4. Anatomy of a Replay-Bound Record



A minimal event record (aligned with GuardClaw v0.1.x semantics):

```json

{

"event\_id": "uuid-string",

"timestamp": "2026-02-16T10:00:00Z",

"event\_type": "intent | execution | result | failure",

"subject\_id": "agent-finance-01",

"action": "EXECUTE\_TRADE",

"nonce": "32-hex-character-string",

"correlation\_id": "optional-string-or-null",

"metadata": { "optional": "object-or-null" }

}

```



A corresponding cryptographic signature is computed over the canonical representation of all signed fields.



Verification \*\*MUST\*\* reconstruct the canonical representation prior to signature validation.



\*\*Note:\*\*  

The signature may be stored as a separate field, envelope wrapper, or JSONL record entry depending on implementation.



The schema above reflects GuardClaw v0.1.x semantics. Implementations may vary, provided invariants are preserved.



---



\## 5. What Replay-Bound Evidence Does NOT Guarantee



Replay-Bound Evidence does not guarantee:

\- That the event reflects external reality

\- That the decision was correct

\- That malicious actions were prevented

\- That keys were not compromised

\- That timestamps are authoritative (see Section 6.1)

\- That files were not deleted at lower maturity levels



\### ⚠️ Fundamental Limitation: The Oracle Problem



Replay-Bound Evidence proves:



> What was recorded and signed.



It does not prove:



> That the external world corresponds to that record.



This framework addresses \*\*accountability\*\*, not truth verification.



---



\## 6. Threat Model and Scope



Replay-Bound Evidence \*\*defends against\*\*:

\- Post-hoc log modification

\- Undetected event duplication

\- Signature repudiation

\- Silent alteration of recorded data



It \*\*does not defend against\*\*:

\- Key compromise

\- Malicious agents signing false claims

\- Timestamp manipulation without anchoring

\- File deletion at lower maturity levels

\- Full infrastructure compromise



Security boundaries must be explicitly understood.



---



\### 6.1 Timestamp Limitations



System-generated timestamps (Level 2–3):

\- Provide relative ordering

\- Do not prove authoritative wall-clock time



Authoritative time proof requires external timestamp authorities (e.g., RFC 3161) and corresponds to Level 4 maturity.



---



\## 7. Ledger-Local Integrity vs. Global Consensus



Replay-Bound Evidence does not require distributed consensus.



Unlike blockchain systems:

\- No global agreement mechanism

\- No proof-of-work or proof-of-stake

\- No network-wide state

\- No economic consensus layer



Replay protection operates within a defined ledger domain.



This is \*\*ledger-local integrity\*\*, not global consensus.



---



\## 8. Relation to Existing Work



Relevant standards include:

\- Certificate Transparency (RFC 6962)

\- Evidence Record Syntax (RFC 4998)

\- W3C Verifiable Credentials

\- NIST SP 800-53 Audit Controls

\- ISO/IEC 27037 Digital Evidence Handling

\- Blockchain-based immutability systems



Replay-Bound Evidence differs by:

\- Targeting AI agent event accountability

\- Avoiding mandatory distributed consensus

\- Introducing subject-scoped replay invariants

\- Defining minimal implementable properties



---



\## 9. Evidence Maturity Model



\### Level 0 — Basic Logging

Mutable records. No cryptographic binding.



\### Level 1 — Signed Events

Events cryptographically signed. No replay protection.



\### Level 2 — Replay-Bound Evidence

Signed events with subject-scoped replay detection and offline verification.



\### Level 3 — Chained Integrity

Hash chaining or Merkle structures, gap detection, file deletion detection.



\### Level 4 — Anchored Provenance

External timestamp authorities, key rotation audit trails, genesis identity anchoring, cross-system verifiability.



---



\## 10. Why This Matters Now



\### 10.1 Regulatory Evolution



Emerging regulatory frameworks increasingly require traceability and integrity controls for high-risk AI systems.



While language varies across jurisdictions, expectations around tamper-resistance and adversarial verification are rising.



\### 10.2 Liability and Governance



As AI systems transition from recommendation to execution, disputes increasingly depend on reconstructing decision history.



Governance and legal processes now routinely ask:



> Can you demonstrate the integrity of historical records?



Cryptographic auditability strengthens evidentiary posture.



\### 10.3 Procurement and Risk Evaluation



Enterprise AI deployments increasingly include:

\- Security reviews

\- Governance assessments

\- Auditability requirements



Verifiable event integrity is becoming a meaningful evaluation factor.



Replay-Bound Evidence defines a baseline maturity threshold.



---



\## 11. Implementation Considerations



Minimal implementation requires:

1\. Cryptographic signing

2\. Per-subject uniqueness constraint

3\. Canonical serialization

4\. Public key distribution

5\. Deterministic verification logic



\### 11.1 Performance Considerations



Representative Ed25519 cryptographic benchmarks (e.g., PyNaCl and Python cryptography library implementations on modern x86 hardware):



\- \*\*Signing\*\* (cryptographic operation only): ~0.05 ms

\- \*\*Verification\*\* (cryptographic operation only): ~0.02 ms

\- \*\*Storage overhead\*\*: ~400–800 bytes per signed event



These figures exclude I/O and storage latency.



---



\## 12. Open Questions and Future Work



\- Cross-ledger replay detection

\- Key compromise recovery

\- Verifiable timing without centralized trust

\- Multi-agent scalability

\- Privacy-preserving deletion



---



\## 13. Conclusion



Observability is not evidence.  

Logging is not proof.  

Trust is not verification.



Replay-Bound Evidence defines a minimal foundation for cryptographically verifiable agent accountability.



It provides cryptographic evidence of what was recorded.



Nothing more. Nothing less.



---



\## 14. Security Considerations



Replay-Bound Evidence defines minimal cryptographic properties for tamper-evident event recording. It does not claim comprehensive adversarial resistance across all threat models.



\### 14.1 Log Truncation and Withholding



Level 2 does not guarantee ledger completeness. An attacker may delete tail events without invalidating earlier signatures.



\*\*Level 2 guarantees:\*\*

\- Tamper detection for included records

\- Replay detection within provided ledger scope



\*\*It does not guarantee:\*\*

\- Detection of omitted records

\- Detection of truncation

\- Detection of withholding



Implementers \*\*SHOULD\*\* evaluate whether Level 2 is sufficient for their threat model.



\### 14.2 Canonicalization Divergence



Cross-language JSON canonicalization may cause signature verification divergence.



Replay-Bound Evidence does not mandate RFC 8785 compliance at Level 2.



Implementers \*\*SHOULD\*\* constrain payload formats appropriately.



\### 14.3 Key Compromise



Replay-Bound Evidence proves what key signed an event. It does not prove key storage security or environment integrity.



\### 14.4 Identity Binding



Level 2 does not define PKI, certificate binding, or institutional identity anchoring.



\### 14.5 Timestamp Authority



System timestamps provide relative ordering only. Authoritative time requires Level 4 anchoring.



\### 14.6 Concurrency



Uniqueness enforcement across distributed runtime instances remains an implementation responsibility.



\### 14.7 Scope of Guarantees



Replay-Bound Evidence guarantees cryptographic intent, not ground truth.



\*\*It proves:\*\*

\- What was signed

\- That included records were not modified

\- That duplication within scope is detectable



\*\*It does not prove:\*\*

\- External reality

\- Infrastructure security

\- Global completeness



---



\## Appendix A — Reference Implementation



\*\*GuardClaw v0.1.x\*\* implements Level 2 Replay-Bound Evidence:

\- Ed25519 signing

\- Subject-scoped nonce replay protection

\- Canonical JSON serialization

\- Offline CLI verification



\*\*Repository:\*\* https://github.com/viruswami5511/guardclaw



GuardClaw is a reference implementation of the Replay-Bound Evidence framework.



---

