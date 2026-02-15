# GuardClaw Threat Model

**Document status:** Canonical (v0.1.0)  
**Audience:** Security reviewers, contributors, early adopters  
**Scope:** Cryptographically signed event emission and replay verification  

---

## 0. Purpose of This Document

GuardClaw v0.1.0 is a **verifiable event logging substrate**.

It provides:

- Cryptographically signed event records
- Tamper detection via signature verification
- Per-agent nonce-based replay detection
- Offline verification via CLI

It does **not** implement policy enforcement, distributed consensus,
delegation chains, or durable replay state.

This document defines what GuardClaw v0.1.0:

- Guarantees
- Detects
- Cannot protect against

---

## 1. Security Model (v0.1.0)

### What GuardClaw Guarantees

If evidence exists and private keys are secure:

1. **Event Integrity**
   - Signed events cannot be modified without detection.

2. **Attribution**
   - Events are cryptographically bound to a signing key.

3. **Replay Detection (Ledger-Local)**
   - Duplicate nonces for the same agent are detectable during replay.

4. **Offline Verifiability**
   - Anyone with the public key can verify signatures offline.

5. **Tamper Evidence**
   - Signature failure results in explicit verification error.

---

### What GuardClaw Does NOT Guarantee

GuardClaw v0.1.0 does not guarantee:

- Prevention of malicious actions
- Enforcement of policy decisions
- Durable replay protection across restarts
- Cross-ledger replay prevention
- Distributed consensus
- Absolute timestamp correctness
- Protection against stolen private keys
- File deletion detection
- Immutable storage
- Recovery from root key loss

These are intentional scope boundaries.

---

## 2. Threat Classification

Each scenario is categorized as:

- ✅ Prevented by design  
- ⚠️ Detectable but not prevented  
- ❌ Out of scope  

---

## 3. Threat Scenarios

---

### 3.1 Event Tampering

**Scenario**  
An attacker modifies event data after it is signed.

**Classification:** ✅ Prevented by design

**Reason**  
Any modification invalidates the Ed25519 signature.

---

### 3.2 Replay Within Same Ledger

**Scenario**  
An attacker re-inserts an old signed event into the same ledger.

**Classification:** ⚠️ Detectable but not prevented

**Reason**  
Duplicate nonces per agent are flagged during replay.

**Limitation**  
Replay detection is per-ledger and not durable across restarts.

---

### 3.3 Replay Across Systems

**Scenario**  
An attacker replays a valid signed event to a different system.

**Classification:** ❌ Out of scope

**Reason**  
Nonce tracking is ledger-local only.

---

### 3.4 Timestamp Manipulation

**Scenario**  
An operator alters system clock before emitting events.

**Classification:** ⚠️ Detectable but not prevented

**Reason**  
GuardClaw guarantees signature integrity, not wall-clock truth.

---

### 3.5 Key Compromise

**Scenario**  
An attacker steals a private signing key.

**Classification:** ❌ Out of scope

**Reason**  
Valid signatures cannot distinguish when signing occurred.

Mitigation requires key rotation and external controls.

---

### 3.6 File Deletion

**Scenario**  
An attacker deletes entire ledger files.

**Classification:** ❌ Out of scope

**Reason**  
v0.1.0 does not implement hash chaining or Merkle structures.

---

### 3.7 Disk Full / Write Failure

**Scenario**  
Ledger write fails due to resource exhaustion.

**Classification:** ⚠️ Detectable but not prevented

**Reason**  
Subsequent verification reveals missing evidence window.

---

### 3.8 Cryptographic Library Vulnerability

**Scenario**  
Ed25519 implementation flaw is discovered.

**Classification:** ❌ Out of scope

**Reason**  
All cryptographic systems inherit underlying algorithm risk.

---

## 4. Summary Table

| Threat | Classification |
|--------|---------------|
| Event tampering | ✅ Prevented |
| Same-ledger replay | ⚠️ Detectable |
| Cross-system replay | ❌ Out of scope |
| Timestamp manipulation | ⚠️ Detectable |
| Key compromise | ❌ Out of scope |
| File deletion | ❌ Out of scope |
| Disk exhaustion | ⚠️ Detectable |
| Crypto library flaw | ❌ Out of scope |

---

## 5. Design Philosophy (v0.1.0)

GuardClaw prioritizes:

- Cryptographic integrity over enforcement
- Explicit limitations over marketing claims
- Offline verifiability over convenience
- Narrow, correct guarantees over broad promises

---

## 6. Final Statement

GuardClaw v0.1.0 provides:

Provable integrity of signed events and ledger-local replay detection.

It does not claim to solve authorization, enforcement, consensus,
or distributed trust.

Future versions may extend these capabilities.
v0.1.0 does not.