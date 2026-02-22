# GuardClaw Threat Model (v0.1.3)

Status: Alpha  
Audience: Security reviewers, contributors, early adopters  
Scope: Cryptographically signed event emission and ledger-local replay verification  

---

## 1. Purpose

GuardClaw v0.1.3 is a cryptographic evidence ledger for autonomous agent accountability.

It provides:

- Signed event emission
- Deterministic canonical serialization
- Ledger-local nonce-based replay detection
- Tamper-evident verification
- Offline verification via CLI

It does not implement:

- Policy enforcement
- Distributed consensus
- Delegation chains
- Durable replay state
- Hash chaining
- Immutable storage guarantees

This document defines:

- What GuardClaw guarantees
- What it detects
- What is explicitly out of scope

---

## 2. Security Model Summary

### If private keys remain secure:

GuardClaw guarantees:

1. **Event Integrity**
   - Signed events cannot be modified without detection.

2. **Cryptographic Attribution**
   - Events are bound to a signing key.

3. **Ledger-Local Replay Detection**
   - Duplicate nonces for the same `subject_id` are detectable during verification.

4. **Offline Verifiability**
   - Anyone with the public key can verify signatures without network access.

5. **Loud Failure**
   - Signature or schema violations result in explicit verification errors.

---

## 3. Explicit Non-Guarantees

GuardClaw v0.1.3 does NOT guarantee:

- Prevention of malicious actions
- Authorization correctness
- Durable replay protection across restarts
- Cross-ledger replay prevention
- Distributed consensus
- Trusted timestamp authority
- File deletion detection
- Protection against stolen private keys
- Recovery from root key compromise
- Immutable storage guarantees

These boundaries are intentional.

---

## 4. Threat Classification

Each scenario is categorized as:

- ✅ Prevented by design
- ⚠️ Detectable but not prevented
- ❌ Out of scope

---

## 5. Threat Scenarios

---

### 5.1 Event Tampering

**Scenario:**  
An attacker modifies event data after it is signed.

**Classification:** ✅ Prevented by design

**Reason:**  
Any modification invalidates the Ed25519 signature.

---

### 5.2 Ledger-Local Replay

**Scenario:**  
An attacker re-inserts an old signed event into the same ledger.

**Classification:** ⚠️ Detectable but not prevented

**Reason:**  
Duplicate nonces for the same `subject_id` are detected during verification.

**Limitation:**  
Replay tracking is memory-local and not durable across restarts.

---

### 5.3 Cross-System Replay

**Scenario:**  
A valid signed event is replayed in a different system or ledger.

**Classification:** ❌ Out of scope

**Reason:**  
Nonce tracking is scoped to a single ledger only.

---

### 5.4 Timestamp Manipulation

**Scenario:**  
System clock is altered before emitting events.

**Classification:** ⚠️ Detectable but not prevented

**Reason:**  
GuardClaw guarantees signature integrity, not wall-clock truth.

No external timestamp authority is used in v0.1.3.

---

### 5.5 Private Key Compromise

**Scenario:**  
An attacker gains access to the private signing key.

**Classification:** ❌ Out of scope

**Reason:**  
Valid signatures cannot distinguish legitimate signing from malicious signing after compromise.

Mitigation requires external key management and rotation controls.

---

### 5.6 File Deletion

**Scenario:**  
Entire ledger files are deleted.

**Classification:** ❌ Out of scope

**Reason:**  
v0.1.3 does not implement hash chaining or Merkle-based continuity proofs.

Deletion is not detectable.

---

### 5.7 Disk Exhaustion / Write Failure

**Scenario:**  
Ledger writes fail due to resource exhaustion.

**Classification:** ⚠️ Detectable but not prevented

**Reason:**  
Missing evidence becomes visible during later verification.

GuardClaw does not implement guaranteed persistence.

---

### 5.8 Cryptographic Primitive Failure

**Scenario:**  
A vulnerability is discovered in Ed25519 or underlying cryptographic library.

**Classification:** ❌ Out of scope

**Reason:**  
All cryptographic systems inherit the risk of underlying algorithm or implementation failure.

---

## 6. Summary Table

| Threat                      | Classification  |
|-----------------------------|---------------- |
| Event tampering             | ✅ Prevented    |
| Ledger-local replay         | ⚠️ Detectable   |
| Cross-system replay         | ❌ Out of scope |
| Timestamp manipulation      | ⚠️ Detectable   |
| Key compromise              | ❌ Out of scope |
| File deletion               | ❌ Out of scope |
| Disk exhaustion             | ⚠️ Detectable   |
| Cryptographic primitive flaw| ❌ Out of scope |

---

## 7. Design Philosophy

GuardClaw prioritizes:

- Explicit guarantees over broad claims
- Cryptographic integrity over enforcement
- Offline verifiability over operational complexity
- Narrow, correct guarantees over speculative assurances

GuardClaw proves what was recorded.

It does not prevent actions.
