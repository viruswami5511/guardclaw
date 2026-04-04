# GuardClaw Evidence Format — GEF-SPEC-1.0

> **Status:** Stable (Ledger Protocol) · **Applies to:** GuardClaw v0.7.x

GEF-SPEC-1.0 defines a **deterministic, verifiable execution history format for autonomous systems**.

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Scope and Non-Goals](#2-scope-and-non-goals)
3. [Envelope Schema](#3-envelope-schema)
4. [Canonical Serialization](#4-canonical-serialization)
5. [Signing Model](#5-signing-model)
6. [Hash Chain Construction](#6-hash-chain-construction)
7. [Ledger Structure](#7-ledger-structure)
8. [Verification Model](#8-verification-model)
9. [Replay and Nonce Semantics](#9-replay-and-nonce-semantics)
10. [Security Properties](#10-security-properties)
11. [Versioning](#11-versioning)
12. [Design Philosophy](#12-design-philosophy)

---

## 1. Purpose

GuardClaw is a **cryptographic execution ledger** for autonomous agent accountability.

GEF-SPEC-1.0 defines:

- The envelope schema (`ExecutionEnvelope`)
- Canonical serialization (RFC 8785 JCS)
- Hash-chain construction
- Signature model (Ed25519)
- Verification rules and failure conditions

GuardClaw is an **evidence substrate**:

- It proves what was recorded.
- It does **not** enforce policy, block actions, or provide consensus.

---

## 2. Scope and Non-Goals

**GEF-SPEC-1.0 guarantees:**

| Guarantee | Description |
|---|---|
| Tamper detection | Detects modification of payload, metadata, or structure |
| Order integrity | Detects reordering via sequence + hash chain |
| Deletion detection | Detects gaps and truncations |
| Signature authenticity | Ed25519-bound to a keypair |
| Offline verifiability | Requires only the ledger file + public key |

**GEF-SPEC-1.0 does not provide:**

- Authorization / policy engines
- Settlement or business logic
- Distributed consensus or BFT
- Trusted timestamps (e.g. RFC 3161)
- Key management or rotation schemes
- Cross-system replay prevention

> GuardClaw is designed to be embedded into systems that provide those layers.

---

## 3. Envelope Schema

The atomic unit of the ledger is the **`ExecutionEnvelope`** — a JSON object with the following fields:

```jsonc
{
  "gef_version":       "1.0",
  "record_id":         "c2e0e2c4-5bb1-4c8f-8e51-7d37a1d2f5a1",
  "record_type":       "execution",   // genesis | intent | execution | result | failure
  "agent_id":          "agent-001",
  "signer_public_key": "<base64url-ed25519-pubkey>",
  "sequence":          41,
  "nonce":             "b8f7da0e6c9246f5a37bf1f1d1c5b435",
  "timestamp":         "2025-12-01T12:34:56.789012Z",
  "causal_hash":       "0000000000000000000000000000000000000000000000000000000000000000",
  "payload":           { },
  "signature":         "<base64url-ed25519-signature>"
}
```

### 3.1 Field Requirements

| Field | Requirement |
|---|---|
| `gef_version` | MUST equal `"1.0"` for GEF-SPEC-1.0 |
| `record_id` | MUST be globally unique. UUIDv4 STRONGLY RECOMMENDED |
| `record_type` | MUST be one of: `genesis`, `intent`, `execution`, `result`, `failure` |
| `agent_id` | MUST be a non-empty string identifying the logical agent |
| `signer_public_key` | MUST be a base64url-encoded Ed25519 public key |
| `sequence` | MUST be an integer ≥ 0, starting at `0` for genesis, increasing by `+1` |
| `nonce` | MUST be cryptographically random, ≥ 128 bits entropy, unique within ledger |
| `timestamp` | MUST be an ISO-8601 UTC timestamp with timezone `Z` |
| `causal_hash` | MUST equal `GENESIS_HASH` for sequence 0; SHA-256 of previous signing surface otherwise |
| `payload` | MUST be valid JSON; semantics are application-defined |
| `signature` | MUST be a base64url-encoded Ed25519 detached signature over the signing surface |

**`record_type` mode behaviour:**

- In **strict mode** — implementations MUST reject unknown values.
- In **forward-compatible mode** — implementations MAY ignore unknown values to allow interoperability with future spec versions (e.g., GEF-SPEC-v1.1).
- Implementations MUST document which mode they operate in.

> ⚠️ Missing or malformed fields MUST cause verification failure.

---

## 4. Canonical Serialization

GEF-SPEC-1.0 uses deterministic canonical JSON encoding based on **RFC 8785 JCS** for the signing surface.

The signing surface consists of the entire envelope object **excluding the `signature` field**. All other fields — `gef_version`, `record_id`, `record_type`, `agent_id`, `signer_public_key`, `sequence`, `nonce`, `timestamp`, `causal_hash`, `payload` — MUST be included in the canonicalized structure.

### 4.1 Canonicalization Rules

| Rule | Requirement |
|---|---|
| Encoding | UTF-8 |
| Key ordering | Sorted JSON object keys |
| Whitespace | No insignificant whitespace |
| Numbers | No `NaN`/`Infinity`; only JSON-valid numbers |
| Strings | Stable representation for identical logical values |

Given identical input envelopes, compliant implementations MUST produce identical canonical byte representations, hashes, and signature verification results.

> This determinism is what makes GEF a **protocol**, not just a library convention.

---

## 5. Signing Model

### 5.1 Algorithm

- Ed25519 (RFC 8032) MUST be used.
- `signer_public_key` MUST be the public key corresponding to the private key used.

### 5.2 Signing Surface

The signing surface is the canonical JSON object that **excludes** the `signature` field:

```jsonc
{
  "gef_version":       "...",
  "record_id":         "...",
  "record_type":       "...",
  "agent_id":          "...",
  "signer_public_key": "...",
  "sequence":          41,
  "nonce":             "...",
  "timestamp":         "...",
  "causal_hash":       "...",
  "payload":           { }
}
```

**Signing procedure:**

1. Construct the signing surface by removing `signature` from the envelope.
2. Canonicalize via RFC 8785 JCS.
3. Compute Ed25519 signature over the canonical bytes.
4. Encode the signature as base64url and store it in `signature`.

> Any modification to any signed field changes the canonical bytes and invalidates the signature.

---

## 6. Hash Chain Construction

The ledger is a JSONL file (`.gef`), append-only, one envelope per line.

### 6.1 Genesis Record

For the genesis envelope (`sequence == 0`):

- `record_type` MUST be `genesis`.
- `causal_hash` MUST equal `GENESIS_HASH`.
- All other invariants (schema, signature, canonicalization) MUST hold.

**`GENESIS_HASH`** is defined as 32 zero bytes, encoded as a 64-character lowercase hexadecimal string:

```
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
```

> ⚠️ All implementations MUST use this exact value. Any other value in the genesis `causal_hash` field MUST cause verification failure. Implementation-defined variation is not permitted — it would break cross-implementation interoperability, which is a core protocol guarantee.

### 6.2 Non-Genesis Records

For each envelope with `sequence == N` where `N > 0`:

- `sequence` MUST equal `N`.
- `causal_hash` MUST equal:

```
SHA256( canonical_signing_surface( entry at sequence N-1 ) )
```

Where `canonical_signing_surface` is the canonical JCS bytes of the previous envelope's signing surface (all fields except `signature`).

### 6.3 Chain Head

The **chain head hash** is defined as:

```
chain_head_hash     = SHA256( canonical_signing_surface( last_entry ) )
chain_head_sequence = last_entry.sequence
```

This pair commits to the entire ledger history and can be externalized for anchoring (Git, RFC 3161 timestamping, transparency logs, etc.).

---

## 7. Ledger Structure

| Property | Value |
|---|---|
| Physical format | JSONL (`.gef` extension RECOMMENDED) |
| Line structure | Each non-empty line MUST contain exactly one `ExecutionEnvelope` |
| Mutation model | Logically **append-only** |
| Deletion markers | None defined in GEF-SPEC-1.0 |

**Implications:** Truncation, deletion, or insertion of lines breaks sequence and/or hash-chain invariants. Verification detects such manipulations as chain violations.

---

## 8. Verification Model

Verification is performed by a **Replay Engine** over a ledger file.

- `signer_public_key` MUST remain consistent across all entries within a ledger.
- If a different `signer_public_key` is observed in any entry after genesis, verification MUST fail with `SIGNER_MISMATCH`.

### 8.1 Inputs

- Ledger file (`.gef`)
- Expected `signer_public_key` (optional, depending on verifier policy)

### 8.2 Check Set and Order

Implementations MAY internally optimize execution order, but MUST produce a deterministic failure result for a given input. The first reported failure MUST be consistent across runs within the same implementation.

For each non-empty line:

| # | Check | Failure Code |
|---|---|---|
| 1 | JSON decode | `MALFORMED_JSON` |
| 2 | Schema validation against envelope schema | `SCHEMA_VIOLATION` |
| 3 | Signature presence (`signature` MUST exist) | `MISSING_SIGNATURE` |
| 4 | Signature encoding (MUST be valid base64url) | `INVALID_SIGNATURE_ENCODING` |
| 5 | Signature crypto (Ed25519 verification MUST pass) | `INVALID_SIGNATURE` |
| 6 | Genesis check (first entry MUST be `genesis` using `GENESIS_HASH`) | `GENESIS_MISSING` |
| 7 | Sequence continuity (`sequence` MUST be contiguous from 0) | `SEQUENCE_GAP` |
| 8 | GEF version consistency (`gef_version` MUST be identical across all entries) | `GEF_VERSION_MISMATCH` |
| 9 | Causal hash (MUST match SHA-256 of previous signing surface) | `CAUSAL_HASH_MISMATCH` |
| 10 | Nonce uniqueness (duplicate nonce within ledger MUST cause failure) | `DUPLICATE_NONCE` |

Any failure produces a **`VerificationSummary`** containing at least:

```jsonc
{
  "total_entries":    <integer>,
  "chain_valid":      <bool>,
  "failure_sequence": <integer | null>,
  "failure_type":     "<FAILURE_CODE | null>",
  "failure_detail":   "<string | null>"
}
```

### 8.3 Verification Modes

| Mode | Behaviour | Unknown `record_type` |
|---|---|---|
| **Strict** | Fails on first violation. Ledger is invalid. | MUST cause failure |
| **Recovery** | Verifies up to last valid prefix; returns partial integrity info | MUST be reported |
| **Forward-compatible** | Enforces all cryptographic invariants; tolerates unknown types | MAY be ignored |

### 8.4 Mode Selection

- Verification mode MUST be explicitly selected by the caller.
- Implementations MUST NOT silently switch modes.
- If no mode is specified, implementations MUST default to **strict mode**.
- The selected mode MUST be exposed in the verification result.

---

## 9. Replay and Nonce Semantics

GEF-SPEC-1.0 uses **random nonce with ledger-local uniqueness** as its replay-resistance mechanism.

| Rule | Requirement |
|---|---|
| Presence | Every envelope MUST contain a `nonce` |
| Randomness | MUST be cryptographically random |
| Uniqueness | Duplicate nonce within ledger MUST fail with `DUPLICATE_NONCE` |
| Scope | Ledger-local only — cross-ledger replay prevention is out of scope |

> Replay protection in GEF-SPEC-1.0 is best-effort within a single file, not a global guarantee. Stronger replay models (subject-scoped monotonic nonces) are defined in GEF-SPEC-v1.1.

---

## 10. Security Properties

Assuming private keys remain secret and the verification procedure is followed:

**GuardClaw provides:**

| Property | Description |
|---|---|
| **Tamper detection** | Any modification to signed fields, sequence, or chain structure is detectable |
| **Order integrity** | Reordering, inserting, or dropping entries breaks sequence and/or hash chain |
| **Deletion detection** | Truncation or removal of entries changes the chain head and/or sequence |
| **Authenticity** | Entries are bound to an Ed25519 keypair; signatures prove origin at the key level |
| **Offline verification** | Requires only the ledger file and the relevant public key |

**Explicitly out of scope:**

| Non-guarantee | Notes |
|---|---|
| Durable replay protection | Across processes or systems |
| Key compromise resistance | Private key security is the caller's responsibility |
| Trusted timestamps | Use RFC 3161 externally if required |
| Canonical ledger consensus | No BFT or distributed agreement |
| Confidentiality | GEF is about integrity, not encryption |
| Key rotation | Not supported in GEF-SPEC-1.0; defined in GEF-SPEC-v1.1 |

---

## 11. Versioning

| Version | Description |
|---|---|
| **GEF-SPEC-1.0** | First stable specification of the GuardClaw Evidence Format |
| **1.x** | Minor revisions MAY add fields in a backward-compatible way |
| **2.0+** | Major revisions MAY introduce breaking changes; documented as new specs |

Ledger entries MUST include `gef_version` so verifiers can select the appropriate validation rules.

---

## 12. Design Philosophy

| Principle | Description |
|---|---|
| **Explicit guarantees** | List exactly what is guaranteed and what is not |
| **Loud failure over silent corruption** | Any deviation from the spec fails verification clearly and early |
| **Verifiability over convenience** | Append-only, canonicalization, and signatures are prioritized over ease of mutation |
| **Narrow, correct guarantees over broad promises** | GuardClaw is an integrity layer, not a full security stack |

---

> GuardClaw proves what was recorded.
> It does **not** decide what should have happened.
> It gives you cryptographic truth about agent execution, so policy, governance, and law have something solid to stand on.
