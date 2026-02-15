# Scope of Truth

**Document Version:** 1.0  
**Protocol Version:** 3.0  
**Status:** NORMATIVE SPECIFICATION  
**Last Updated:** February 10, 2026

---

## Purpose

This document defines **exactly what GuardClaw proves** and **what it explicitly does not prove**.

This boundary is intentional and legally significant.

---

## GuardClaw’s Truth Contract

GuardClaw is an **accountability system**, not a correctness or safety system.

It proves:
> “Who did what, when, under whose authority — and what evidence exists.”

It does **not** prove:
> “Whether the action was correct, safe, or desirable.”

---

## What GuardClaw PROVES

### 1. Authority

- Which keys were authorized
- Which agents acted
- Which delegations existed

---

### 2. Integrity

- Evidence is tamper-evident
- Signatures are verifiable
- Records cannot be silently modified

---

### 3. Sequence

- Event ordering
- Causal chains
- Delegation flows

---

### 4. Temporal Accuracy

- When execution occurred
- When evidence was signed
- Accountability lag is disclosed

---

### 5. Absence

- Observer liveness via heartbeats
- Explicit absence via tombstones
- Detectable gaps

---

## What GuardClaw DOES NOT PROVE

### ❌ Correctness

GuardClaw does not validate:
- Logic correctness
- Output accuracy
- Model quality

---

### ❌ Safety

GuardClaw does not:
- Prevent harmful actions
- Enforce safety constraints
- Guarantee ethical behavior

---

### ❌ Policy Compliance

GuardClaw does not:
- Enforce policy
- Block violations
- Decide compliance outcomes

---

### ❌ Intent Authenticity

GuardClaw records declared intent — it does not prove sincerity.

---

## Why These Limits Exist

### Design Rationale

Combining accountability with enforcement creates:
- Performance bottlenecks
- Legal ambiguity
- Single points of failure

GuardClaw intentionally avoids this.

---

## Legal Significance

Clear scope boundaries:
- Increase admissibility
- Reduce liability confusion
- Prevent overclaiming

GuardClaw evidence is strongest when it is **precise and limited**.

---

## Summary Table

| Question | GuardClaw Answers |
|-------|------------------|
| Who acted? | ✅ Yes |
| What happened? | ✅ Yes |
| When did it happen? | ✅ Yes |
| Under whose authority? | ✅ Yes |
| Was it correct? | ❌ No |
| Was it safe? | ❌ No |
| Should it have happened? | ❌ No |

---

**Document Status:** FINAL  
**Next Review:** Phase 6