# GuardClaw Threat Model

**Status:** Stable  
**Version:** v0.5.1  
**Protocol:** GEF-SPEC-1.0  
**Audience:** Security reviewers, contributors, enterprise evaluators  
**Scope:** Cryptographic evidence ledger for AI agent accountability  

Full security specification: [SPEC.md Section 11](SPEC.md)

---

## 1. Purpose

GuardClaw v0.5.1 implements GEF-SPEC-1.0 — a cryptographic accountability protocol for autonomous AI agents.

It provides:

- Ed25519 per-envelope signing (RFC 8032)
- SHA-256 causal hash chaining over RFC 8785 canonical bytes
- Active nonce uniqueness enforcement (INV-29)
- Sequence gap detection
- Tamper-evident offline verification
- 33 formally defined protocol invariants (45/45 tests passing)
- Cross-language verifiability (Python + Go byte-identical)

It does not provide:

- Policy enforcement
- Distributed consensus
- Authorization control
- Key compromise detection
- Tail truncation detection without external anchoring
- Trusted timestamp authority (Level 4 — future)

---

## 2. Security Model Summary

### If private keys remain secure:

GuardClaw guarantees:

1. **Event Integrity**  
   Any modification to any field of any signed envelope — including `timestamp`, `sequence`, `agent_id`, or `payload` — invalidates the Ed25519 signature. Detection is certain.

2. **Causal Chain Integrity**  
   The SHA-256 hash chain binds every envelope to its predecessor. Inserting, deleting, or reordering any entry breaks the chain hash of every subsequent entry. Detection is certain.

3. **Replay Protection**   
   The replay engine actively scans all nonces during verification. Duplicate nonces within a ledger are detected and reported as `schema` violations (INV-29).

4. **Offline Verifiability**  
   Any party holding the `signer_public_key` can verify a complete ledger without network access, shared secrets, or infrastructure trust.

5. **Loud Failure**  
   Every violation produces a typed `ChainViolation` object (`invalid_signature`, `chain_break`, `sequence_gap`, `schema`) with `.at_sequence` and `.detail`. Verification never silently passes a broken ledger.

---

## 3. Explicit Non-Guarantees

GuardClaw v0.5.1 does NOT guarantee:

- Prevention of malicious actions by the agent
- Authorization or policy correctness
- Cross-ledger replay prevention
- Tail truncation detection (requires external anchoring — Level 4)
- Trusted wall-clock time (timestamps are operator-asserted)
- Protection against stolen private keys
- Immutable storage at the OS/filesystem level

These boundaries are intentional. See the Evidence Maturity Model in [docs/replay-bound-evidence-v1.0.md](docs/replay-bound-evidence-v1.0.md).

---

## 4. Threat Classification

- ✅ Detected and provable by design
- ⚠️ Detectable within defined scope
- ❌ Out of scope

---

## 5. Threat Scenarios

### 5.1 Event Tampering

**Scenario:** An attacker modifies any field of a signed envelope.

**Classification:** ✅ Detected by design

**Mechanism:** Ed25519 signature verification fails. The `signer_public_key` is embedded in the signing surface — key substitution also breaks the chain hash of the next entry.

---

### 5.2 Record Insertion

**Scenario:** An attacker injects a new record between two existing records.

**Classification:** ✅ Detected by design

**Mechanism:** The injected record's `causal_hash` will not match SHA-256(JCS(prev.signing_surface)). Chain break reported at the injection point and every subsequent entry.

---

### 5.3 Record Deletion

**Scenario:** An attacker deletes a record from the middle of the ledger.

**Classification:** ✅ Detected by design

**Mechanism:** Sequence gap detection (INV-25) and chain break at the next entry. Both violations are reported.

---

### 5.4 Record Reordering

**Scenario:** An attacker reorders records within the ledger.

**Classification:** ✅ Detected by design

**Mechanism:** Both sequence gaps and chain breaks are detected.

---

### 5.5 Replay Attack (Within Ledger)

**Scenario:** A captured valid envelope is re-inserted into the same ledger.

**Classification:** ✅ Detected by design

**Mechanism:** INV-29 — the replay engine actively scans all nonces. Duplicate nonce reported as `schema` violation. Chain break also reported because the re-inserted envelope's `causal_hash` will not match the expected value at its position.

---

### 5.6 Tail Truncation

**Scenario:** An attacker deletes records from the end of the ledger.

**Classification:** ⚠️ Detectable with external anchoring only

**Mechanism:** A truncated ledger passes all seven verification steps against its remaining records. Truncation is not detectable by a verifier operating on the ledger alone.

**Mitigation:** Periodically publish the chain head hash to an external transparency log or RFC 3161 timestamp authority. This is Level 4 in the Evidence Maturity Model.

---

### 5.7 Timestamp Manipulation

**Scenario:** System clock is altered before emitting envelopes.

**Classification:** ⚠️ Detectable with external anchoring only

**Reason:** `timestamp` is in the signing surface — it cannot be modified after signing. However, it reflects operator-asserted time, not
authoritative wall-clock time. RFC 3161 anchoring (Level 4) provides authoritative time proof.

---

### 5.8 Private Key Compromise

**Scenario:** An attacker obtains the private signing key.

**Classification:** ❌ Out of scope

**Reason:** A compromised key allows production of valid-appearing new records. It does not allow retroactive modification of existing records without breaking the chain hash. Key rotation requires creating a new ledger. Multi-key support is planned for a future minor version (GEF-SPEC-1.1).

---

### 5.9 Cross-Ledger Replay

**Scenario:** A valid envelope from one ledger is replayed into another. 
**Classification:** ❌ Out of scope (ledger-local integrity only)

**Reason:** GEF v1.0 provides ledger-local integrity. Cross-ledger replay prevention requires application-layer controls.

---

### 5.10 Cryptographic Primitive Failure

**Scenario:** A vulnerability is found in Ed25519, SHA-256, or RFC 8785.

**Classification:** ❌ Out of scope

**Reason:** Standard inheritance risk. A new `gef_version` with updated
primitives is required per SPEC.md Section 14.

---

## 6. Summary Table

| Threat | Classification |
|---|---|
| Event field tampering | ✅ Detected |
| Record insertion | ✅ Detected |
| Record deletion (middle) | ✅ Detected |
| Record reordering | ✅ Detected |
| Replay within ledger | ✅ Detected (INV-29 + chain) |
| Tail truncation | ⚠️ External anchoring required |
| Timestamp manipulation | ⚠️ External anchoring required |
| Key compromise | ❌ Out of scope |
| Cross-ledger replay | ❌ Out of scope |
| Cryptographic primitive flaw | ❌ Out of scope |

---

## 7. Design Philosophy

GuardClaw prioritizes:

- Cryptographic proof over operational trust
- Offline verifiability over SaaS dependency
- Explicit guarantees over broad claims
- Narrow, correct invariants over speculative assurances

GuardClaw proves what was recorded.  
It does not prevent actions.
