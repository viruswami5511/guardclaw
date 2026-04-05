# GuardClaw Evidence Format — GEF-SPEC-1.0

Status: Stable (Ledger Protocol)  
Applies to: GuardClaw v0.7.x

GEF-SPEC-1.0 defines a **deterministic, verifiable execution history format for autonomous systems**.

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

GEF-SPEC-1.0 guarantees:

- Tamper detection (payload, metadata, structure)
- Order integrity (sequence + hash chain)
- Deletion detection (gaps and truncations)
- Signature authenticity (Ed25519)
- Offline verifiability from a ledger file + public key

GEF-SPEC-1.0 does **not** provide:

- Authorization / policy engines  
- Settlement or business logic  
- Distributed consensus or BFT  
- Trusted timestamps (e.g. RFC 3161)  
- Key management or rotation schemes  
- Cross-system replay prevention

GuardClaw is designed to be embedded into systems that provide those layers.

---

## 3. Envelope Schema

The atomic unit of the ledger is the **ExecutionEnvelope**.

Each envelope is a JSON object with the following fields:

```jsonc
{
  "gef_version": "1.0",
  "record_id": "c2e0e2c4-5bb1-4c8f-8e51-7d37a1d2f5a1",
  "record_type": "execution",          // genesis | intent | execution | result | failure
  "agent_id": "agent-001",
  "signer_public_key": "64-hex-ed25519-pubkey",
  "sequence": 41,
  "nonce": "b8f7da0e6c9246f5a37bf1f1d1c5b435",
  "timestamp": "2025-12-01T12:34:56.789012Z",
  "causal_hash": "000000...0000",      // genesis sentinel or previous entry hash
  "payload": {
    // application-defined JSON payload
  },
  "signature": "base64url-ed25519-signature"
}
```

### 3.1 Field Requirements

- `gef_version`  
  - MUST equal `"1.0"` for GEF-SPEC-1.0.

- `record_id`  
  - MUST be globally unique.  
  - UUIDv4 is STRONGLY RECOMMENDED.

- `record_type`  
  - MUST be one of: `genesis`, `intent`, `execution`, `result`, `failure`.  
  - Implementations MAY restrict supported record types but MUST reject unknown values.

- `agent_id`  
  - MUST be a non-empty string identifying the logical agent.

- `signer_public_key`  
  - MUST be exactly 64 lowercase hexadecimal characters (32‑byte Ed25519 public key).

- `sequence`  
  - MUST be an integer >= 0.  
  - MUST start at 0 for the genesis record.  
  - MUST increase monotonically by +1 for each subsequent entry.

- `nonce`  
  - MUST exist.  
  - MUST be cryptographically random.  
  - SHOULD provide at least 128 bits of entropy (e.g., 32+ hex characters).  

- `timestamp`  
  - MUST be an ISO-8601 UTC timestamp with timezone `Z`.

- `causal_hash`  
  - For the genesis entry (`sequence == 0`):  
    - MUST be equal to `GENESIS_HASH` (see Â§6.1).  
  - For all subsequent entries:  
    - MUST equal the SHA-256 digest of the **canonical signing surface** of the previous entry.

- `payload`  
  - MUST be valid JSON.  
  - Semantics are application-defined and out of scope.

- `signature`  
  - MUST be a base64url-encoded Ed25519 detached signature over the signing surface.

Missing or malformed fields MUST cause verification failure.

---

## 4. Canonical Serialization

GEF-SPEC-1.0 uses deterministic canonical JSON encoding based on **RFC 8785 JCS** for the signing surface.

The signing surface consists of the entire envelope object **excluding the `signature` field**.  All other fields (`gef_version`, `record_id`, `record_type`, `agent_id`, `signer_public_key`, `sequence`, `nonce`, `timestamp`, `causal_hash`, `payload`) MUST be included in the canonicalized structure.

### 4.1 Canonicalization Rules

- UTF-8 encoding  
- Sorted JSON object keys  
- No insignificant whitespace  
- No NaN/Infinity; only JSON-valid numbers  
- String representation is stable for identical logical values  

Given identical input envelopes, compliant implementations MUST produce identical canonical byte representations, hashes, and signature verification results.

This determinism is what makes GEF a protocol, not just a library convention.

---

## 5. Signing Model

### 5.1 Algorithm

- Ed25519 (RFC 8032) MUST be used.
- `signer_public_key` MUST be the public key corresponding to the private key used.

### 5.2 Signing Surface

The signing surface is a canonical JSON object that **excludes** the `signature` field:

```jsonc
{
  "gef_version": "...",
  "record_id": "...",
  "record_type": "...",
  "agent_id": "...",
  "signer_public_key": "...",
  "sequence": 41,
  "nonce": "...",
  "timestamp": "...",
  "causal_hash": "...",
  "payload": { ... }
}
```

Signing procedure:

1. Construct the signing surface by removing `signature` from the envelope.  
2. Canonicalize via RFC 8785 JCS.  
3. Compute Ed25519 signature over the canonical bytes.  
4. Encode the signature as base64url and store it in `signature`.

Any modification to any signed field changes the canonical bytes and invalidates the signature.

---

## 6. Hash Chain Construction

The ledger is a JSONL file (`.gef`), append-only, one envelope per line.

### 6.1 Genesis Record

For the genesis envelope (`sequence == 0`):

- `record_type` MUST be `genesis`.  
- `causal_hash` MUST equal `GENESIS_HASH`.  
- All other invariants (schema, signature, canonicalization) MUST hold.

**GENESIS_HASH** is defined as 32 zero bytes, encoded as a 64-character lowercase hex string:

```text
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
```

All implementations MUST use this exact value for the genesis `causal_hash`.

### 6.2 Non-Genesis Records

For each envelope with `sequence == N` where `N > 0`:

- `sequence MUST equal the zero-based index of the entry within the ledger.`.  
- `causal_hash` MUST equal:

```text
SHA256( canonical_signing_surface(sequence == N-1) )
```

Where `canonical_signing_surface(sequence == N-1)` is the canonical JCS bytes
of the previous envelope’s signing surface.

### 6.3 Chain Head

The **chain head hash** is defined as:

```text
chain_head_hash = SHA256( canonical_signing_surface(last_entry) )
chain_head_sequence = last_entry.sequence
```

This pair (`chain_head_hash`, `chain_head_sequence`) commits to the entire ledger history and can be externalized (e.g., for anchoring in Git, RFC 3161 timestamping, or other systems).

---

## 7. Ledger Structure

- Physical format: **JSONL** (`.gef` extension RECOMMENDED).  
- Each non-empty line MUST contain exactly one `ExecutionEnvelope` JSON object.  
- The ledger is logically **append-only**.  
- No in-band deletion markers are defined in GEF-SPEC-1.0.

**Implications:**

- Truncation, deletion, or insertion of lines will break sequence and/or hash-chain invariants.  
- Verification detects such manipulations as chain violations.

Lines MAY be terminated by a newline character (`\n`).

Empty lines SHOULD be ignored by verifiers and MUST NOT affect verification results.

---

## 8. Verification Model

Verification is performed by a **Replay Engine** over a ledger file.

### 8.1 Inputs

- Ledger file (`.gef`)  
- Expected `signer_public_key` (optional, depending on verifier policy)

### 8.2 Check Set and Order

If signature verification fails for any entry, the ledger MUST be considered invalid. Implementations SHOULD report this as `INVALID_SIGNATURE` or equivalent.

The following checks MUST be performed. Implementations MAY reorder checks as long as all invariants are enforced before declaring the ledger valid.

For each non-empty line:

1. **JSON decode**  
2. **Schema validation** against the envelope schema  
3. **Signature presence** (`signature` MUST exist)  
4. **Signature encoding** (base64url)  
5. **Signature crypto** (Ed25519 verification)  
6. **Genesis check** (first entry MUST be `genesis` and use `GENESIS_HASH`)  
7. **Sequence continuity** (`sequence` MUST be contiguous from 0)  
8. **GEF version consistency** (`gef_version` MUST match across ledger)  
9. **Causal hash** (`causal_hash` MUST match hash of previous signing surface)  
10. **Nonce checks** (MUST exist; duplicate nonce is a violation)

Any failure produces a **VerificationSummary** containing at least:

- `total_entries`  
- `chain_valid` (bool)  
- `failure_sequence` (line/sequence context)  
- `failure_type`  
- `failure_detail`  

`failure_type` SHOULD be drawn from a well-defined set of invariant violations (e.g., `MALFORMED_JSON`, `SCHEMA_VIOLATION`, `INVALID_SIGNATURE`, `SEQUENCE_GAP`, `CAUSAL_HASH_MISMATCH`, `DUPLICATE_NONCE`, `GENESIS_MISSING`). The exact enumeration is implementation-defined but MUST be stable within a
given implementation version.

### 8.3 Modes

- **Strict mode**  
  - Fails on the first violation; the ledger is considered invalid.

- **Recovery mode**  
  - Verifies entries up to the last valid prefix.  
  - Returns partial integrity information (trusted prefix, integrity boundary hash, etc.).

Details of the `VerificationSummary` structure are implementation-specific but MUST expose:

- Whether the full chain is valid  
- How many entries were processed  
- Where and why verification failed (if it did)

---

## 9. Replay and Nonce Semantics

GEF-SPEC-1.0 uses **nonce presence and uniqueness checks** as a basic replay-resistance
mechanism within a ledger.

Rules:

- Every envelope MUST contain a `nonce`.  
- If the same nonce appears more than once within a ledger, verification MUST flag it as a chain violation
  (e.g., `DUPLICATE_NONCE`).  
- Nonce scope is **ledger-local**. Cross-ledger replay prevention is out of scope.

Replay protection is **best-effort within a single file**, not a global guarantee.

---

## 10. Security Properties

Assuming private keys remain secret and the verification procedure is followed:

GuardClaw provides:

- **Tamper detection**  
  Any modification to signed fields, sequence, or chain structure is detectable.

- **Order integrity**  
  Reordering, inserting, or dropping entries breaks sequence and/or hash chain.

- **Deletion detection**  
  Truncation or removal of entries changes the chain head and/or sequence.

- **Authenticity**  
  Entries are bound to an Ed25519 keypair; signatures prove origin at the key level.

- **Offline verification**  
  Verification requires only the ledger file and the relevant public key.

Non-guarantees (explicitly out of scope):

- Durable replay protection across processes or systems  
- Key compromise resistance  
- Trusted timestamps  
- Consensus on â€œtheâ€ canonical ledger  
- Confidentiality (GEF is about integrity, not encryption)

---

## 11. Versioning

- **GEF-SPEC-1.0** is the first stable specification of the GuardClaw Evidence Format.  
- Minor revisions (1.x) MAY add fields in a backward-compatible way with clear migration rules.  
- Major revisions (2.0+) MAY introduce breaking changes and will be documented as new specs.

Ledger entries MUST include `gef_version` so verifiers can select the appropriate validation rules.

---

## 12. Design Philosophy

GuardClaw follows these principles:

- **Explicit guarantees**  
  List exactly what is guaranteed and what is not.

- **Loud failure over silent corruption**  
  Any deviation from the spec fails verification clearly and early.

- **Verifiability over convenience**  
  Append-only, canonicalization, and signatures are prioritized over ease of mutation.

- **Narrow, correct guarantees over broad promises**  
  GuardClaw is an integrity layer, not a full security stack.

GuardClaw proves what was recorded.  
It does **not** decide what should have happened.  
It gives you cryptographic truth about agent execution, so policy, governance, and law have something solid to stand on.