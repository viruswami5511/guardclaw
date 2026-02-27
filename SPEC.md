# GuardClaw Execution Framework (GEF)

# Protocol Specification — Version 1.0



***



```

Document ID   : GEF-SPEC-1.0

Status        : STABLE

Published     : 2026-02-27

Authors       : GuardClaw Protocol Team

Repository    : https://github.com/viruswami5511/guardclaw

PyPI          : https://pypi.org/project/guardclaw

License       : Apache License 2.0

Supersedes    : (none — initial specification)

```



***



## Abstract



The GuardClaw Execution Framework (GEF) is a cryptographic accountability protocol for AI agent systems. GEF defines a tamper-evident, append-only evidence ledger in which every record is individually signed with Ed25519 and causally linked to every record that preceded it via a SHA-256 hash chain over RFC 8785 canonicalized JSON.



GEF is language-neutral. Any implementation that reproduces the three protocol contracts defined in Section 6 will produce byte-identical chain hashes and successfully verify signatures produced by any other compliant implementation, regardless of programming language, operating system, or runtime environment.



This document is the authoritative specification of the GEF protocol. It defines the data model, the three contracts, the formal invariants, the verification procedure, the ledger format, security properties, and the compliance requirements for new implementations.



***



## Status of This Document



This document specifies **GEF Protocol Version 1.0**, which is the first stable release of the specification. It is published alongside the reference implementation (`guardclaw` v0.5.0, Python) and a verified cross-language proof demonstrating byte-identical behavior between the Python reference implementation and an independent Go implementation.



The specification is stable. Breaking changes require a new major version (`GEF-SPEC-2.0`) and a corresponding migration path. Additive changes (new record types, new optional fields) may be published as minor amendments without incrementing the major version.



***



## Table of Contents



```

1\.  Introduction

&nbsp;   1.1  Why a Protocol, Not a Library

2\.  Design Goals

3\.  Terminology

4\.  Protocol Overview

5\.  The Envelope

&nbsp;   5.1  Field Definitions

&nbsp;   5.2  Field Encoding Rules

&nbsp;   5.3  Record Types

6\.  The Three Protocol Contracts

&nbsp;   6.1  Contract I  — Canonical Serialization (RFC 8785 JCS)

&nbsp;   6.2  Contract II — Causal Chain Integrity (SHA-256)

&nbsp;   6.3  Contract III — Signature Authenticity (Ed25519)

7\.  Signing and Verification Procedure

&nbsp;   7.1  Constructing the Signing Surface

&nbsp;   7.2  Signing an Envelope

&nbsp;   7.3  Verifying an Envelope Signature

&nbsp;   7.4  Verifying a Full Ledger

8\.  Chain Construction

&nbsp;   8.1  Genesis Entry

&nbsp;   8.2  Subsequent Entries

&nbsp;   8.3  Chain Hash Algorithm

9\.  The Ledger Format

&nbsp;   9.1  Encoding

&nbsp;   9.2  Append Semantics

&nbsp;   9.3  Crash Consistency

10\. Formal Invariants

&nbsp;   10.1  Signing Invariants        (INV-01 – INV-08)

&nbsp;   10.2  Chain Invariants          (INV-09 – INV-14)

&nbsp;   10.3  Schema Invariants         (INV-15 – INV-22)

&nbsp;   10.4  Replay Invariants         (INV-23 – INV-28)

&nbsp;   10.5  Nonce Invariants          (INV-29 – INV-30)

&nbsp;   10.6  Cross-Language Invariants (INV-31 – INV-33)

11\. Security Considerations

&nbsp;   11.1  Threat Model

&nbsp;   11.2  Cryptographic Choices and Rationale

&nbsp;   11.3  Attack Surface Analysis

&nbsp;   11.4  Known Limitations

&nbsp;   11.5  Ledger Anchoring

12\. Cross-Language Compliance

&nbsp;   12.1  Compliance Requirements

&nbsp;   12.2  Test Vectors

&nbsp;   12.3  Verified Implementations

13\. Implementation Guidance

14\. Versioning

&nbsp;   14.1  Version Identifier

&nbsp;   14.2  Major Version — Breaking Changes

&nbsp;   14.3  Minor Version — Additive Changes

&nbsp;   14.4  Ledger Homogeneity

&nbsp;   14.5  Forward Compatibility for Record Types

15\. Compliance Declaration

16\. Non-Normative Design Rationale

&nbsp;   16.1  Why a Chain Hash, Not a Merkle Tree

&nbsp;   16.2  Why the Chain Hash Excludes the Signature

&nbsp;   16.3  Why Ed25519 and Not RSA or ECDSA (P-256)

&nbsp;   16.4  Why RFC 8785 JCS and Not Protocol Buffers or MessagePack

&nbsp;   16.5  Why JSONL and Not a Database Format

&nbsp;   16.6  Why Ten Signing Fields and Not More

&nbsp;   16.7  Why Apache 2.0 and Not MIT or GPL

17\. References



Appendix A: Field Quick Reference

Appendix B: Violation Type Registry

Appendix C: Record Type Registry and Governance

Appendix D: Signing Surface Field Order (Informative)

```



***



## 1. Introduction



AI agent systems — systems that perceive, decide, and act autonomously — introduce a category of accountability problem that conventional logging does not address. A log entry asserts that something happened. It does not prove it. Logs can be amended, truncated, or silently rewritten. The agent that produced the log and the system that stores it are typically the same party, creating an unverifiable self-report.



GEF addresses this problem at the protocol level. Every action taken by a GEF-compliant agent is recorded as a cryptographically signed envelope. The agent's Ed25519 private key signs a canonical representation of the record. Every subsequent record includes the SHA-256 hash of its predecessor's canonical representation, forming an immutable causal chain. No record in the chain can be altered, inserted, or deleted without invalidating every record that follows it.



The result is not a log. It is an **evidence ledger** — a chain of cryptographic proof that an agent did what it claims to have done, in the order it claims to have done it, without post-hoc modification.



### 1.1  Why a Protocol, Not a Library



GEF is defined as a protocol so that:



1\. Any language can implement it from this specification alone, without access to the reference implementation.



2\. A verifier written in any language can verify a ledger produced by any other compliant implementation.



3\. The protocol can outlive any single implementation. The reference implementation can be deprecated, replaced, or rewritten. The ledgers it produced remain verifiable by any future implementation that conforms to this specification.



This is the same architectural decision that made Git portable across every operating system, and that made OCI images runnable on every container runtime. The hash is the contract, not the code.



***



## 2. Design Goals



**G-1  Tamper Evidence.**

Any modification to any field of any envelope — including metadata fields such as `timestamp`, `sequence`, or `agent_id` — must break the cryptographic proof. A verifier must be able to detect the modification without access to the original author.



**G-2  Causal Chain Integrity.**

The order of events must be cryptographically enforced. An entry cannot be inserted before, between, or after any other entry without detection. Reordering the ledger must be detectable.



**G-3  Language Neutrality.**

The protocol must be implementable in any language that has access to Ed25519 cryptography, SHA-256, and RFC 8785 JSON Canonicalization. No language-specific serialization format, no binary encoding, no platform dependency.



**G-4  Auditability Without Keys.**

A verifier needs only the signer's public key to verify a complete ledger. Private keys are never required for verification. Any third party with the

public key — a regulator, an auditor, a counterparty — can independently verify the ledger.



**G-5  Append-Only Semantics.**

The ledger is append-only by design. There is no update, no delete, no rewrite. The only valid operation on a ledger is appending a new entry.



**G-6  Crash Consistency.**

A partial write (system crash during append) must not corrupt the existing ledger. The corrupted or partial entry is detectable and isolatable. All preceding entries remain verifiable.



**G-7  Minimal Specification Surface.**

The protocol is defined by three contracts, ten signing fields, and four record types. The specification is intentionally minimal. Every field has a reason. No field is optional for signing purposes.



***



## 3. Terminology



The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.



**Envelope.**

A single GEF record. The atomic unit of the evidence ledger. An envelope is a JSON object with exactly the fields defined in Section 5.



**Ledger.**

An ordered, append-only sequence of GEF envelopes stored in JSONL format (one envelope per line).



**Signing surface.**

The JSON object constructed from an envelope's fields for the purpose of computing a signature. The `signature` field is excluded. Defined formally in Section 7.1.



**Canonical bytes.**

The byte representation of the signing surface produced by applying RFC 8785 JSON Canonicalization Scheme (JCS). Canonical bytes are deterministic: identical inputs produce identical byte sequences on any conformant JCS implementation.



**Causal hash.**

The SHA-256 digest, encoded as a 64-character lowercase hex string, of the canonical bytes of the previous envelope's signing surface. The `causal_hash` stored in entry N is the hash of entry N-1's signing surface. Also referred to informally as "chain hash" — the two terms are synonymous in this specification. The field name `causal_hash` is normative.



**Genesis hash.**

The sentinel `causal_hash` value for the first entry in a ledger:

64 zero characters (`"0000000000000000000000000000000000000000000000000000000000000000"`).

Indicates that no predecessor exists.



**Genesis entry.**

The first entry in a ledger. The genesis entry has `sequence: 0` and `causal_hash` equal to the genesis hash.



**Nonce.**

A 32-character lowercase hex string (128 bits of cryptographically random entropy) included in every envelope. The nonce provides global uniqueness.

Two envelopes with identical payload, timestamp, and `agent_id` will still differ in their nonce, ensuring distinct signatures and preventing replay attacks.



**Sequence number.**

A zero-based, monotonically increasing integer (0, 1, 2, …). Every envelope in a ledger has a unique sequence number. The genesis entry is always `sequence: 0`. Each subsequent entry increments by exactly 1.



**Violation.**

A detected inconsistency in a ledger: a broken causal hash link, an invalid signature, a schema error, or a sequence gap. See Appendix B for the complete violation type registry.



**Replay.**

The process of loading a ledger and verifying every entry in sequence. Replay produces a `ReplaySummary` containing the verification result and all detected violations.



**Compliant implementation.**

An implementation of the GEF protocol that satisfies all requirements in Section 6 and passes the test vectors in Section 12.2.



***



## 4. Protocol Overview



A GEF ledger is produced by an agent that holds an Ed25519 key pair. For each action the agent takes, it:



```

1\. Constructs an Envelope with the action's metadata and payload.

2\. Computes the causal_hash from the previous envelope's signing surface (or the genesis hash for the first entry).

3\. Assigns the next monotonically increasing sequence number.

4\. Generates 128 bits of cryptographic randomness as the nonce.

5\. Constructs the signing surface (all fields except signature).

6\. Applies RFC 8785 JCS to produce canonical bytes.

7\. Signs the canonical bytes with its Ed25519 private key.

8\. Encodes the signature as base64url (no padding).

9\. Sets the signature field and appends the completed envelope to the ledger.

```



A verifier (any party holding the agent's public key) can at any time:



```

1\. Load the ledger line by line.

2\. For each entry:

&nbsp;  a. Verify the schema is well-formed (all required fields present and valid).

&nbsp;  b. Verify the sequence is monotonically increasing with no gaps.

&nbsp;  c. Verify causal_hash == SHA-256(JCS(prev.signing_surface)).

&nbsp;  d. Verify the Ed25519 signature over JCS(signing_surface).

3\. Emit a summary: chain valid, all signatures valid, no violations.

```



The verifier requires no private keys, no shared secrets, no connection to the agent, and no access to the original system. The ledger file and the public key are sufficient.



```

┌──────────────────────────────────────────────────────────────────────┐

│  AGENT                          LEDGER                  VERIFIER                            │

│                                                                                             │

│  Ed25519 key pair               ledger.jsonl            public key                          │

│       │                              │                      │                              │

│  \[action]                            │                      │                              │

│       │                              │                      │                              │

│  construct envelope                  │                      │                              │

│  compute causal_hash                 │                      │                              │

│  assign sequence + nonce             │                      │                              │

│  JCS(signing_surface) ──────────►│                      │                              │

│  Ed25519.Sign(canonical_bytes)       │                      │                              │

│  append to ledger ─────────────►│                      │                              │

│                                      │                      │                              │

│                                      │◄─── load ────────│                              │

│                                      │     verify chain     │                              │

│                                      │     verify sigs      │                              │

│                                      │     emit summary ──►│                              │

└──────────────────────────────────────────────────────────────────────┘

```



***



## 5. The Envelope



A GEF envelope is a JSON object. When stored in the ledger, it is serialized as a single JSON line (JSONL). When signed or hashed, only the signing surface (Section 7.1) is used — not the full envelope JSON.



### 5.1  Field Definitions



An envelope has exactly **eleven fields** when stored in the ledger (ten signing fields plus `signature`). No additional fields are permitted. No fields may be omitted.



| Field           | Type   | Description |

|---              |--      |--          -|

| `gef_version`   | string | Protocol version. MUST be `"1.0"` for this specification. |

| `record_id`     | string | Globally unique identifier for this envelope. RECOMMENDED format: UUID v4. MUST be non-empty. |

| `record_type`   | string | Semantic type of this record. See Section 5.3 and Appendix C. |

| `agent_id`      | string | Identifier of the agent that produced this envelope. MUST be non-empty. |

| `signer_public_key` | string | Ed25519 public key of the signing agent, encoded as 64 lowercase hexadecimal characters (32 bytes). |

| `sequence`      | intege | Zero-based monotonically increasing position in this agent's ledger. MUST be a non-negative integer. |

| `nonce`         | string | 32 lowercase hexadecimal characters (128 bits of cryptographically random entropy). MUST be unique across all envelopes in a ledger. |

| `timestamp`     | string | ISO 8601 UTC timestamp with millisecond precision, ending in `Z`. Format: `YYYY-MM-DDTHH:mm:ss.sssZ`. |

| `causal_hash`   | string | SHA-256 of the canonical bytes of the previous envelope's signing surface, encoded as 64 lowercase hex characters. For the first entry, MUST equal the genesis hash (64 zeros). |

| `payload`       | object | Application-defined JSON object. MUST be a JSON object (not null, not array, not scalar). |

| `signature`     | string | Ed25519 signature over the canonical bytes of the signing surface, encoded as base64url with no padding. Approximately 86 characters. |



### 5.2  Field Encoding Rules



**`gef_version`**

MUST be the string `"1.0"`. All envelopes within a single ledger MUST share an identical `gef_version` value. A ledger with mixed version values MUST be rejected by a verifier.



**`record_id`**

MUST be a non-empty string. UUID v4 format is RECOMMENDED. The record_id MUST be unique within a ledger. Two envelopes with the same `record_id` in the same ledger constitute a schema violation.



**`signer_public_key`** 

MUST be exactly 64 lowercase hexadecimal characters representing the 32-byte Ed25519 public key. Uppercase hex is invalid. A key of incorrect length is a schema violation.



**`sequence`**

MUST be a non-negative integer (≥ 0). The genesis entry MUST have `sequence: 0`. Each subsequent entry MUST increment by exactly 1. A gap (e.g., 0, 1, 3) or repeat (e.g., 0, 1, 1) is a sequence violation.



**`nonce`**

MUST be exactly 32 lowercase hexadecimal characters (16 bytes, 128 bits). MUST be generated from a cryptographically secure random number generator. Uppercase hex is invalid. A nonce of incorrect length is a schema violation.



**`timestamp`**

MUST conform to ISO 8601 UTC with millisecond precision. The format is `YYYY-MM-DDTHH:mm:ss.sssZ` exactly. The trailing `Z` is REQUIRED. Microsecond precision (6 decimal digits) is NOT permitted. Timestamps without `Z` are invalid.



**`causal_hash`**

MUST be exactly 64 lowercase hexadecimal characters. For the genesis entry, MUST equal the genesis hash sentinel:

`"0000000000000000000000000000000000000000000000000000000000000000"`.

For all subsequent entries, MUST equal `SHA-256(JCS(prev_entry.signing_surface))` encoded as 64 lowercase hex.



**`payload`**

MUST be a JSON object (`{}`). An empty object `{}` is valid. A JSON array, null value, string, number, or boolean is NOT permitted as the top-level payload type.



**`signature`**

MUST be a base64url-encoded string with no padding characters (`=`). An Ed25519 signature is 64 bytes, which encodes to 86 base64url characters without padding. The `signature` field MUST NOT be included in the signing surface.



### 5.3  Record Types



The following record types are defined in GEF v1.0. A `record_type` value not in this list is a schema violation. See Appendix C for governance.



| Value      | Semantic |

|---         |---       |

| `execution`| Agent executed an action or tool call |

| `intent`   | Agent declared intent to act (pre-execution declaration) |

| `result`   | Agent recorded the outcome of a prior execution |

| `failure`  | Agent recorded a failure, error, or exception |



***



## 6. The Three Protocol Contracts



GEF's correctness depends on three contracts that every compliant implementation MUST fulfill. An implementation that fulfills all three will be byte-compatible with every other compliant implementation.



### 6.1  Contract I — Canonical Serialization (RFC 8785 JCS)



**Every implementation MUST use RFC 8785 JSON Canonicalization Scheme (JCS) to produce canonical bytes from the signing surface.**



JCS defines a deterministic JSON serialization algorithm:



1\. All insignificant whitespace is removed.

2\. String escaping follows a defined subset of JSON string encoding.

3\. Number serialization follows IEEE 754 with defined special cases.

4\. **Object keys are sorted in ascending Unicode code point order of their UTF-8 encoded byte sequences.**



The canonical bytes of a given JSON object are identical on any conformant JCS implementation, regardless of language, platform, or JSON library. This is the foundation of language neutrality.



An implementation MUST NOT attempt to manually sort keys or construct canonical JSON. It MUST pass the signing surface object to a JCS-conformant library and use that library's output as canonical bytes.



### 6.2  Contract II — Causal Chain Integrity (SHA-256)



**The `causal_hash` of every entry (except the genesis entry) MUST be the SHA-256 digest of the canonical bytes of the previous entry's signing surface, encoded as 64 lowercase hexadecimal characters.**



Formally, for entry at position N (N > 0):



```

causal_hash\[N] = hex(SHA-256(JCS(signing_surface\[N-1])))

```



For the genesis entry (N = 0):



```

causal_hash\[0] = "0000000000000000000000000000000000000000000000000000000000000000"

```



The chain hash is computed over the **signing surface**, not the full ledger JSON. This means the `signature` field of entry N-1 does NOT affect the `causal_hash` of entry N. Chain integrity and signature integrity are independently verifiable.



### 6.3  Contract III — Signature Authenticity (Ed25519)



**Every envelope's `signature` field MUST be the Ed25519 signature of the canonical bytes of the envelope's signing surface, produced using the private key corresponding to `signer_public_key`.**



Ed25519 uses the Edwards25519 curve as specified in RFC 8032. The signature algorithm is deterministic: given the same private key and message, it always produces the same signature. No external source of randomness is required during signing.



Verification:



```

Ed25519.Verify(

&nbsp;   public_key = decode_hex(envelope.signer_public_key),

&nbsp;   message    = JCS(signing_surface(envelope)),

&nbsp;   signature  = base64url_decode(envelope.signature)

) == True

```



A verifier MUST use the `signer_public_key` embedded in the envelope itself for verification. This binds the key identity into the signed content, preventing key substitution attacks.



***



## 7. Signing and Verification Procedure



### 7.1  Constructing the Signing Surface

&nbsp;

The signing surface is a JSON object containing exactly the ten fields listed below, in any order (the JCS library will sort them canonically). The `signature` field MUST be excluded.



```

{

&nbsp; "gef_version":      <string>,

&nbsp; "record_id":        <string>,

&nbsp; "record_type":      <string>,

&nbsp; "agent_id":         <string>,

&nbsp; "signer_public_key": <string>,

&nbsp; "sequence":         <integer>,

&nbsp; "nonce":            <string>,

&nbsp; "timestamp":        <string>,

&nbsp; "causal_hash":      <string>,

&nbsp; "payload":          <object>

}

```



The signing surface MUST contain exactly these ten fields — no more, no fewer. Any implementation that adds, removes, or renames a field in the signing surface will produce different canonical bytes and will fail to interoperate with any other compliant implementation.



### 7.2  Signing an Envelope



```

PROCEDURE Sign(envelope, private_key):



&nbsp; 1. Construct signing_surface from envelope (exclude 'signature').

&nbsp; 2. canonical_bytes = JCS(signing_surface)               // Contract I

&nbsp; 3. sig_bytes       = Ed25519.Sign(private_key, canonical_bytes) // Contract III

&nbsp; 4. envelope.signature = base64url_encode(sig_bytes, padding=False)

&nbsp; 5. RETURN envelope

```



### 7.3  Verifying an Envelope Signature



```

PROCEDURE VerifySignature(envelope) -> bool:



&nbsp; 1. Construct signing_surface from envelope (exclude 'signature').

&nbsp; 2. canonical_bytes = JCS(signing_surface)               // Contract I

&nbsp; 3. public_key_bytes = decode_hex(envelope.signer_public_key)

&nbsp; 4. sig_bytes        = base64url_decode(envelope.signature)

&nbsp; 5. RETURN Ed25519.Verify(public_key_bytes, canonical_bytes, sig_bytes)

```



If step 5 returns False, emit violation type `invalid_signature` for this entry. Continue verification of subsequent entries.



### 7.4  Verifying a Full Ledger



```

PROCEDURE VerifyLedger(ledger_path, public_key) -> ReplaySummary:



&nbsp; entries    = load_jsonl(ledger_path)

&nbsp; violations = \[]

&nbsp; prev       = None

&nbsp; seen_nonces = {}     // empty set



&nbsp; FOR i, entry IN enumerate(entries):



&nbsp;   // Phase 1 — Schema

&nbsp;   schema_errors = ValidateSchema(entry)

&nbsp;   IF schema_errors:

&nbsp;     violations.append(Violation("schema", i, schema_errors))

&nbsp;     CONTINUE   // cannot verify chain or sig for malformed entry



&nbsp;   // Phase 1 — Sequence

&nbsp;   expected_seq = i

&nbsp;   IF entry.sequence != expected_seq:

&nbsp;     violations.append(Violation("sequence_gap", i,

&nbsp;       expected=expected_seq, actual=entry.sequence))



&nbsp;   // Phase 1 — Chain

&nbsp;   IF i == 0:

&nbsp;     expected_hash = GENESIS_HASH

&nbsp;   ELSE:

&nbsp;     expected_hash = hex(SHA-256(JCS(signing_surface(prev))))

&nbsp;   IF entry.causal_hash != expected_hash:

&nbsp;     violations.append(Violation("chain_break", i,

&nbsp;       expected=expected_hash, actual=entry.causal_hash))



&nbsp;  // Phase 1 — Nonce uniqueness

&nbsp;  IF entry.nonce IN seen_nonces:

&nbsp;     violations.append(Violation("schema", i,

&nbsp;     detail="Duplicate nonce — nonces MUST be unique per ledger"))

&nbsp;      seen_nonces.add(entry.nonce)



&nbsp;   // Phase 2 — Signature

&nbsp;   IF NOT VerifySignature(entry):

&nbsp;     violations.append(Violation("invalid_signature", i))



&nbsp;   prev = entry



&nbsp; RETURN ReplaySummary(

&nbsp;   total_entries   = len(entries),

&nbsp;   violations      = violations,

&nbsp;   chain_valid     = not any(v.type in ("chain_break","sequence_gap") for v in violations),

&nbsp;   signatures_valid= not any(v.type == "invalid_signature" for v in violations),

&nbsp;   schema_valid    = not any(v.type == "schema" for v in violations),

&nbsp; )

```



***



## 8. Chain Construction



### 8.1  Genesis Entry



The genesis entry is the first entry appended to a new ledger. It MUST:



- Have `sequence: 0`

- Have `causal_hash` equal to the genesis hash sentinel:

&nbsp; `"0000000000000000000000000000000000000000000000000000000000000000"`

- Be signed with the agent's Ed25519 private key

- Have a valid nonce, timestamp, and all other required fields



### 8.2  Subsequent Entries



For every entry after the genesis entry, the producer MUST:



1\. Obtain the `signing_surface` of the immediately preceding entry.

2\. Compute `causal_hash = hex(SHA-256(JCS(signing_surface)))`.

3\. Set `sequence = prev.sequence + 1`.

4\. Generate a fresh nonce (128 bits of cryptographic randomness).

5\. Set `timestamp` to the current UTC time with millisecond precision.

6\. Sign the new envelope per Section 7.2.



### 8.3  Chain Hash Algorithm



```

FUNCTION ComputeCausalHash(prev_envelope) -> string:

&nbsp; signing_surface = ConstructSigningSurface(prev_envelope)

&nbsp; canonical_bytes = JCS(signing_surface)

&nbsp; digest          = SHA-256(canonical_bytes)

&nbsp; RETURN lowercase_hex(digest)   // always 64 characters

```



The SHA-256 digest is encoded as exactly 64 lowercase hexadecimal

characters. Uppercase hex is NOT permitted in `causal_hash` values.



***



## 9. The Ledger Format



### 9.1  Encoding



A GEF ledger is a text file in JSONL format (JSON Lines). Each line is one complete, self-contained JSON envelope. Lines are separated by a single newline character (`\\n`, U+000A). Carriage return (`\\r`) MUST NOT appear as the sole line terminator; `\\r\\n` is tolerated by readers but MUST NOT be produced by writers.



The file MUST be UTF-8 encoded. No BOM (byte order mark) is permitted.



A valid ledger file satisfies all of the following:

- Each line is a valid JSON object.

- Each JSON object contains exactly the eleven fields defined in Section 5.

- The sequence of objects forms a valid GEF chain (Sections 6.2, 8).

- All signatures are valid (Section 6.3).



The recommended file extension is `.jsonl`. Example: `agent.jsonl`.



### 9.2  Append Semantics



The ledger is strictly append-only. A producer MUST:



1\. Open the file in append mode.

2\. Write one complete JSON line (envelope + `\\n`) as a single write operation.

3\. Flush and close (or fsync if durability is required).



A producer MUST NOT:

- Overwrite any existing line.

- Truncate the file.

- Reorder existing lines.

- Delete any existing entry.



A verifier that detects evidence of rewriting (e.g., chain breaks in the middle of an otherwise intact ledger) MUST report a `chain_break` violation.



### 9.3  Crash Consistency



If the system crashes during an append:



- **Scenario A: Crash before write completes.** The file remains valid up to the last fully written line. The partial line, if any, is invalid JSON and MUST be treated as a schema violation for that line only. All preceding entries remain verifiable.



- **Scenario B: Crash after write, before fsync.** The entry may or may not be present depending on OS buffering. If it is absent, the ledger is valid up to the previous entry. If it is present and complete, it is a valid entry.



A verifier encountering a trailing partial line MUST:

1\. Record a `schema` violation for the partial line.

2\. Report the violation in the ReplaySummary.

3\. Continue to report results for all preceding entries (which are valid).



A partial trailing line MUST NOT cause the verifier to report prior entries as invalid.



***



## 10. Formal Invariants



This section defines 33 invariants that a compliant implementation MUST satisfy. These invariants are the normative test surface: a test suite that demonstrates all 33 invariants pass on an implementation constitutes evidence of GEF compliance.



### 10.1  Signing Invariants (INV-01 – INV-08)



**INV-01** A properly signed envelope MUST verify using the `signer_public_key` embedded in that envelope.



**INV-02** Mutating the `payload` field of a signed envelope MUST cause signature verification to return False.



**INV-03** Mutating the `record_type` field of a signed envelope MUST cause signature verification to return False.



**INV-04** Mutating the `timestamp` field of a signed envelope MUST cause signature verification to return False.



**INV-05** Mutating the `agent_id` field of a signed envelope MUST cause signature verification to return False.



**INV-06** Mutating the `nonce` field of a signed envelope MUST cause signature verification to return False.



**INV-07** Mutating the `sequence` field of a signed envelope MUST cause signature verification to return False.

&nbsp;

**INV-08** Mutating the `gef_version` field of a signed envelope MUST cause signature verification to return False.



### 10.2  Chain Invariants (INV-09 – INV-14)



**INV-09** The `causal_hash` of the genesis entry (sequence 0) MUST equal the genesis hash sentinel (64 zero characters).



**INV-10** The `causal_hash` of entry N (N > 0) MUST equal the SHA-256 of the JCS canonical bytes of entry N-1's signing surface, encoded as

64 lowercase hex characters.



**INV-11** Mutating the `payload` of entry N-1 after entry N is constructed MUST break the chain verification for entry N (i.e., the stored `causal_hash` of entry N will no longer match the recomputed hash of the mutated entry N-1).



**INV-12** Mutating the `record_id` of entry N-1 MUST break the chain verification for entry N.



**INV-13** A chain of N signed envelopes where each entry was produced per the protocol MUST fully verify (no chain breaks, no signature failures) for any N ≥ 1.



**INV-14** Injecting a new entry between positions M and M+1 in an existing chain MUST produce a chain break violation at position M+1 (the original entry M+1 now has a `causal_hash` that does not match the injected entry). 



### 10.3  Schema Invariants (INV-15 – INV-22)



**INV-15** An envelope with an unregistered `record_type` value MUST be rejected at construction time (the producer MUST raise an error).



**INV-16** An envelope with an unregistered `record_type` value injected into the raw JSON MUST be detected by the schema validator and reported as a `schema` violation.



**INV-17** A `nonce` field that is not exactly 32 lowercase hex characters MUST be detected by the schema validator.



**INV-18** A `timestamp` field that does not end with `Z` MUST be detected by the schema validator. 



**INV-19** A `timestamp` field with microsecond precision (6 decimal digits) MUST be detected by the schema validator.



**INV-20** A `signer_public_key` that is not exactly 64 lowercase hex characters MUST be detected by the schema validator.



**INV-21** A `payload` that is not a JSON object (e.g., an array, null, string, or number) MUST be rejected at construction time.



**INV-22** A `sequence` that is a negative integer MUST be rejected at construction time.



### 10.4  Replay Invariants (INV-23 – INV-28)



**INV-23** The replay engine MUST detect a chain break in a JSONL ledger and report it as a `chain_break` violation with the correct sequence

position.



**INV-24** The replay engine MUST detect a forged signature (one produced by a different key) and report it as an `invalid_signature` violation.



**INV-25** The replay engine MUST detect a sequence gap (e.g., sequence jumps from 1 to 3) and report it as a `sequence_gap` violation.



**INV-26** The replay engine MUST detect a ledger containing envelopes with mixed `gef_version` values and report a `schema` violation.



**INV-27** The replay engine MUST detect an envelope with a missing required field and report it as a `schema` violation.



**INV-28** The `ReplaySummary` produced by the replay engine MUST accurately count total entries, total violations, and violations by type.



### 10.5  Nonce Invariants (INV-29 – INV-30)



**INV-29** Two independently created envelopes MUST NOT share the same nonce value. (This is guaranteed by generating nonces from a cryptographically secure random number generator.)



**INV-29** Two envelopes within the same ledger MUST NOT share the same nonce value. The producer MUST generate nonces from a ryptographically secure random number generator to ensure uniqueness. The replay engine MUST actively scan for duplicate nonces during verification and MUST report a "schema" violation for any nonce that appears more than once in a ledger.





**INV-30** Every nonce produced by the implementation MUST be exactly 32 lowercase hexadecimal characters.



### 10.6  Cross-Language Invariants (INV-31 – INV-33)



**INV-31** The set of fields in the signing surface MUST be identical to the set of fields in the chain dict (the object used to compute `causal_hash`). Both contain exactly the ten fields excluding `signature`.



**INV-32** The JCS canonical bytes produced for a given signing surface MUST be identical across serialize → deserialize round-trips. That is, serializing an envelope to JSON, deserializing it, and recomputing canonical bytes MUST produce the same byte sequence.



**INV-33** The `causal_hash` computed before and after a serialize/deserialize round-trip of an envelope MUST be identical.



***



## 11. Security Considerations



### 11.1  Threat Model



GEF is designed to protect against the following threats:



**T-1  Post-hoc record modification.** An adversary modifies one or more fields of a previously signed envelope. GEF detects this via signature verification (Contract III) and chain verification (Contract II).



**T-2  Record insertion.** An adversary inserts a new envelope into the middle of a ledger. GEF detects this via chain verification: the inserted entry's `causal_hash` will not match its predecessor, and the entry following it will have an incorrect `causal_hash` for the new state.



**T-3  Record deletion.** An adversary removes one or more envelopes from the ledger. GEF detects this via sequence gap detection (INV-25) and chain verification (the entry after the deleted entry will have an incorrect `causal_hash`).



**T-4  Record reordering.** An adversary reorders entries in the ledger. GEF detects this via chain verification and sequence gap detection.



**T-5  Signature forgery.** An adversary produces a valid-looking signature without the private key. This is computationally infeasible for Ed25519 under current cryptographic assumptions.



**T-6  Key substitution.** An adversary replaces `signer_public_key` with a key they control and re-signs. GEF detects this because changing `signer_public_key` breaks the chain hash of the next entry (the `signer_public_key` field is part of the signing surface, which is hashed into `causal_hash`).



**T-7  Protocol downgrade.** An adversary replaces `gef_version` with an older version to exploit reduced security requirements. GEF detects this because `gef_version` is in the signing surface; mutating it breaks signature verification.



**T-8  Cross-ledger replay.** An adversary takes a valid envelope from one ledger and inserts it into another. GEF detects this via chain verification (the `causal_hash` will not match) and nonce uniqueness (the nonce is part of the signed content, binding it to its original context).



### 11.2  Cryptographic Choices and Rationale



See Section 16.3 for detailed rationale. Summary:



- **Ed25519** provides 128-bit security level, deterministic signing (no nonce randomness required), compact 64-byte signatures, and resistance to side-channel attacks via constant-time implementations.



- **SHA-256** provides 128-bit collision resistance, is standardized by NIST (FIPS 180-4), and is universally available in all languages and platforms.



- **RFC 8785 JCS** provides deterministic JSON canonicalization without requiring binary encoding, preserving human-readability.



### 11.3  Attack Surface Analysis



The attack surface of a GEF ledger is limited to:



1\. **The private key.** Compromise of the private key allows an adversary to produce valid signatures on new entries. It does not allow retroactive modification of existing entries without breaking the chain hash. However, if the adversary obtains the key before any anchoring commitment (see Section 11.5), they can rebuild the entire ledger.



2\. **The JCS library.** A non-conformant JCS library that produces non-deterministic output will produce signatures that verify on the same platform but fail on other platforms. This is a compliance defect, not a security vulnerability.



3\. **The random number generator.** A weak RNG can produce predictable nonces, potentially enabling replay attacks across ledgers. GEF requires a cryptographically secure RNG (CSPRNG) for nonce generation. 



4\. **The verifier implementation.** A verifier that skips chain verification or accepts malformed entries provides weaker guarantees. Verifiers MUST implement all 33 invariants.



### 11.4  Known Limitations



**Limitation 1 — No key revocation in the ledger format.**

GEF v1.0 does not define a mechanism for revoking or rotating signing keys within a ledger. A key rotation produces a new ledger or requires an application-layer convention for the `agent_id` and `signer_public_key` transition.



**Limitation 2 — No multi-party signing.**

GEF v1.0 assumes a single signing key per ledger. Multi-party or threshold signing is not defined.



**Limitation 3 — No built-in payload schema.**

GEF does not validate the contents of the `payload` object. Applications are responsible for defining and validating their own payload schemas.



**Limitation 4 — Private key re-signing attack.**

An agent that holds its own private key can destroy its existing ledger and rebuild a new one from scratch with fabricated history. All entries in the new ledger will have valid signatures and a valid chain. This attack is undetectable from the ledger file alone. Ledger anchoring (Section 11.5) is the recommended mitigation.



### 11.5  Ledger Anchoring



The private key re-signing attack (Limitation 4 above) means that an agent holding its own private key can rebuild and re-sign its entire ledger, producing a fraudulent history that is internally valid. GEF cannot detect this from the ledger file alone.



**Ledger anchoring** is the practice of periodically publishing a commitment to the current ledger state to an immutable external system. Once a commitment is published externally, the ledger cannot be rewritten before that commitment point without contradiction.



Recommended anchoring strategies, in order of assurance:



**Level 1 — Periodic hash publication.**

At regular intervals (e.g., every 1,000 entries, or every hour), publish the following value to an append-only external system:



```

anchor_value = SHA-256(causal_hash_of_last_entry || sequence_number || timestamp)

```

&nbsp;

Suitable external systems: a public transparency log, an immutable object store with write-once semantics, or a public blockchain.



**Level 2 — RFC 3161 Timestamp Authority.**

Submit the `anchor_value` to an RFC 3161-compliant Timestamp Authority (TSA). The TSA issues a signed timestamp token that cryptographically binds the anchor value to a wall-clock time, independently of the agent. This provides legally defensible timestamp evidence and is sufficient for most regulatory compliance requirements.



**Level 3 — Public ledger anchoring.**

Submit the `anchor_value` to a public blockchain or distributed ledger (e.g., Ethereum, Bitcoin via OP_RETURN). This provides maximum non-repudiation: the existence of a specific ledger state at a specific block height is publicly verifiable by anyone, forever, without trusting any single party.



**GEF v1.0 does not mandate anchoring.** It is a RECOMMENDED practice for deployments where any of the following conditions hold:



- The ledger signer and the ledger verifier are different legal entities.

- The ledger may be used as evidence in a dispute.

- The time at which events occurred is legally material.



**Anchoring interval guidance:**



| Deployment context | Recommended interval |

|---        |---     |

| High-assurance (financial, legal, medical) | Every entry or every minute |

| Standard production | Every 1,000 entries or every hour |

| Development / testing | Not required |



**Implementation note.**

Anchoring is orthogonal to the GEF protocol. It does not change the

envelope format, the signing procedure, or the verification procedure.

It is an operational practice layered on top of a valid GEF ledger.



***



## 12. Cross-Language Compliance



### 12.1  Compliance Requirements



A GEF-compliant implementation MUST:



1\. Use RFC 8785 JCS for all canonical serialization (Contract I).

2\. Use SHA-256 for all causal hash computation (Contract II).

3\. Use Ed25519 (RFC 8032) for all signing and verification (Contract III).

4\. Encode public keys as 64 lowercase hex characters.

5\. Encode signatures as base64url with no padding.

6\. Encode chain hashes as 64 lowercase hex characters.

7\. Use the genesis hash sentinel for the first entry's `causal_hash`.

8\. Enforce the eleven-field envelope schema.

9\. Implement all 33 invariants as defined in Section 10.

10\. Produce byte-identical canonical bytes and chain hashes for all

&nbsp;   test vectors in Section 12.2.



### 12.2  Test Vectors



The following test vectors are normative. A compliant implementation MUST produce byte-identical canonical bytes and `causal_hash` values for these inputs.



**Test Vector 1 — Genesis Entry Signing Surface**



Input signing surface (before JCS):

```json

{

&nbsp; "gef_version": "1.0",

&nbsp; "record_id": "550e8400-e29b-41d4-a716-446655440000",

&nbsp; "record_type": "execution",

&nbsp; "agent_id": "agent-test-001",

&nbsp; "signer_public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",

&nbsp; "sequence": 0,

&nbsp; "nonce": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",

&nbsp; "timestamp": "2026-02-26T00:00:00.000Z",

&nbsp; "causal_hash": "0000000000000000000000000000000000000000000000000000000000000000",

&nbsp; "payload": {"action": "initialize"}

}

```



Expected JCS canonical bytes (UTF-8):

```

{"agent_id":"agent-test-001","causal_hash":"0000000000000000000000000000000000000000000000000000000000000000","gef_version":"1.0","nonce":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4","payload":{"action":"initialize"},"record_id":"550e8400-e29b-41d4-a716-446655440000","record_type":"execution","sequence":0,"signer_public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","timestamp":"2026-02-26T00:00:00.000Z"}

```



Expected causal_hash for a subsequent entry pointing to this genesis:

```

SHA-256 of the above canonical bytes, encoded as 64 lowercase hex

```



**Test Vector 2 — Chain Hash Excludes Signature**



Given two envelopes E0 and E1, the `causal_hash` of E1 MUST be

identical regardless of the value of E0's `signature` field, provided

all other fields of E0 are unchanged. An implementation MUST verify this

property: producing E0 with two different signatures (e.g., by resigning

with the same key — which will produce the same deterministic signature

— or for cross-language testing, by substituting a placeholder) MUST NOT

change the `causal_hash` of E1.



**Test Vector 3 — Negative Tests**



For each of the following mutations applied to a signed envelope, the

verification MUST return False:



1\. Any single byte in the `payload` JSON changed.

2\. Any single character in `timestamp` changed.

3\. The `signature` field truncated by one character.

4\. The `signature` field with one character substituted.

5\. The `signer_public_key` changed to a different valid 64-hex string.



### 12.3  Verified Implementations



| Language | Repository | Verified Version | Status |

|---|---|---|---|

| Python (reference) | https://github.com/viruswami5511/guardclaw | v0.5.0 | Stable |

| Go | _(pending submission)_ | — | In progress |



To register a new verified implementation, open a proposal at

`https://github.com/viruswami5511/guardclaw` with evidence of test

vector compliance and all 33 invariants passing.



***



## 13. Implementation Guidance



This section is informative. It provides practical guidance for implementing GEF correctly.



**Use a JCS library, not manual sorting.**

RFC 8785 JCS key sorting is not simply alphabetical. Keys are sorted by the Unicode code point order of their UTF-8 byte sequences. For ASCII keys this is equivalent to alphabetical order, but edge cases exist with non-ASCII characters. Always use a JCS library.



**Generate nonces with os.urandom or equivalent.**

Python: `secrets.token_hex(16)`. Node.js: `crypto.randomBytes(16).toString('hex')`. 

Go: `crypto/rand` package. Never use `random.random()` or a seeded PRNG.



**Use millisecond precision for timestamps.**

`datetime.utcnow()` in Python returns microseconds. Truncate to milliseconds before formatting. The format string is:

`datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.') + f"{datetime.utcnow().microsecond // 1000:03d}Z"`.

Or use: `datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')\[:-3] + 'Z'`.



**Always sign immediately after construction.**

An unsigned envelope (no `signature` field) is not a valid GEF entry.

The pattern `env = Envelope.create(...).sign(key)` should be enforced by the API.



**Open ledger files in append mode with exclusive locking.**

On POSIX systems, use `fcntl.flock` or `fcntl.lockf` to prevent concurrent writers from corrupting the ledger. On Windows, use `msvcrt.locking` or equivalent.



**Verify after every append (optional but recommended).**

In high-assurance deployments, verify the last written entry immediately after appending to detect write errors before they propagate.



**For key storage, use an HSM or encrypted key file.**

The security of the entire ledger depends on the secrecy of the private key. In production deployments, store private keys in a hardware security module (HSM) or an encrypted key store. Never commit private keys to version control.



***



## 14. Versioning



### 14.1  Version Identifier



The GEF protocol version is carried in the `gef_version` field of every envelope and in the specification document identifier (`GEF-SPEC-X.Y`).

The current version is `"1.0"`.



### 14.2  Major Version — Breaking Changes



A major version increment (1.0 → 2.0) is REQUIRED whenever any of the

following changes are made:



**Signing surface changes — always major:**

- Adding, removing, or renaming any field in the signing surface.

- Changing the type or encoding of any signing surface field.

- Changing the set of required fields from eleven to any other number.



**Algorithm changes — always major:**

- Replacing RFC 8785 JCS with any other canonicalization scheme.

- Replacing SHA-256 with any other hash algorithm for chain hashing.

- Replacing Ed25519 with any other signature algorithm.

- Changing the signature encoding (e.g., base64url → hex).



**Chain semantics changes — always major:**

- Changing the genesis hash sentinel value.

- Changing the definition of `causal_hash` (e.g., hashing the full

&nbsp; envelope instead of the signing surface).



**Verification behavior changes — always major:**

- Changing the definition of a chain violation.

- Changing required violation types.



A verifier for GEF v1.0 MUST NOT attempt to verify a GEF v2.0 ledger.

It MUST emit an error and halt.



### 14.3  Minor Version — Additive Changes



A minor version increment (1.0 → 1.1) is used for additive, non-breaking

changes. The following changes are minor:



- Adding new record types to the registry (see Section 14.5).

- Adding new optional metadata fields that are stored in the ledger

&nbsp; JSON but are **NOT** included in the signing surface. Such fields do

&nbsp; not affect canonicalization, chain hashes, or signatures.

- Clarifications to existing normative text that do not change behavior.

- New appendices, new guidance, new non-normative sections.



The following are **NOT** minor changes — they are major:

- Adding any field to the signing surface, even as optional.

- Changing the encoding of any signing surface field.



### 14.4  Ledger Homogeneity



All envelopes in a ledger MUST share the same `gef_version` value. A ledger mixing `"1.0"` and `"1.1"` envelopes is invalid and MUST be rejected by a verifier with a `GEFVersionError`.



A verifier for GEF v1.x MUST accept ledgers with any `gef_version` value of the form `"1.y"` where y ≥ 0.



A verifier for GEF v1.x encountering a ledger with `gef_version` `"2.0"` MUST reject the ledger with a clear error message indicating the version

is unsupported.



### 14.5  Forward Compatibility for Record Types



When a new record type is added in a minor version (e.g., GEF v1.1 adds `"audit"`), the following compatibility rules apply:



- A v1.0 **producer** MUST NOT emit the new record type — it was not   defined in v1.0.

- A v1.0 **verifier** encountering an unknown `record_type` in a ledger whose `gef_version` is `"1.0"` MUST treat it as a schema violation. 

- A v1.0 **verifier** encountering a ledger with `gef_version` `"1.1"` SHOULD accept unknown record types as valid schema and emit a warning, not a violation. This is forward compatibility mode.

- A v1.1 **verifier** MUST accept all record types defined up to and including v1.1.



This rule follows the Postel principle: be strict about what you produce (your own `gef_version`), be lenient about what you accept (higher minor versions).



***



## 15. Compliance Declaration



An implementation MAY declare GEF compliance by including the following statement in its documentation, accompanied by verification evidence:



***



> **GEF Protocol Compliance Declaration**

>

> This implementation conforms to GEF Protocol Specification Version 1.0

> (GEF-SPEC-1.0), published 2026-02-26.

>

> Compliance verified by:

> - Passing all 33 GEF invariants

>   (test suite: `tests/test_gef_invariants.py`)

> - Producing byte-identical canonical bytes and chain hashes for all

>   test vectors in GEF-SPEC-1.0 Section 12.2

> - Successfully verifying signatures produced by the Python reference

>   implementation

> - Passing the negative test (single-byte mutation breaks verification)



***



## 16. Non-Normative Design Rationale



This section explains the reasoning behind key design decisions. It is **non-normative**: nothing in this section creates requirements. Implementors and evaluators may find it useful for understanding why the protocol is specified as it is.



### 16.1  Why a Chain Hash, Not a Merkle Tree



Merkle trees provide efficient membership proofs but add significant implementation complexity. GEF's primary use case — verifying a sequential agent ledger from start to finish — does not require membership proofs. A linear hash chain is sufficient, simpler to implement correctly in any language, and produces a verifier that is easy to audit and reason about.



### 16.2  Why the Chain Hash Excludes the Signature



The `causal_hash` of entry N is computed from the signing surface of entry N-1, which excludes entry N-1's `signature`. This is intentional.



It means chain integrity and signature integrity are independently verifiable. A verifier can confirm the chain is intact even if signature verification is temporarily skipped. It also means the same payload produces the same chain hash regardless of which key signed it — useful when a ledger is handed off between signers during a key rotation.



### 16.3  Why Ed25519 and Not RSA or ECDSA (P-256)



RSA signatures are 256–512 bytes at comparable security levels. Ed25519 signatures are 64 bytes. For a ledger with 1,000,000 entries, this represents a 192–448 MB difference in ledger size from signatures alone.



ECDSA (P-256) requires a random nonce per signature. A weak random number generator can leak the private key via nonce reuse — this is how the PlayStation 3 private key was extracted in 2010. Ed25519 uses a deterministic nonce derived from the private key and message; no random number generator is required for signing.



Ed25519's performance characteristics (~50,000 signatures/sec single-core) are well-matched to the GEF use case.



### 16.4  Why RFC 8785 JCS and Not Protocol Buffers or MessagePack



GEF records are JSON. The protocol is designed to be readable by humans, inspectable with standard tools (`cat`, `jq`, any text editor), and storable in any system that accepts text files. Binary serialization formats (Protocol Buffers, MessagePack, CBOR) sacrifice readability for performance — an acceptable tradeoff in many protocols, but not in one whose primary purpose is accountability and auditability.



RFC 8785 JCS provides canonical JSON — the benefits of a canonical binary format (deterministic byte sequence) without abandoning the human-readability of JSON.



### 16.5  Why JSONL and Not a Database Format



A JSONL ledger file can be:



- Opened in any text editor.

- Processed with `grep`, `jq`, `awk`, or any line-oriented tool.

- Tailed in real time with `tail -f`.

- Appended to with a single `write()` call.

- Copied with `cp` or transferred with any file transfer protocol.

- Committed to a Git repository.

- Archived without a database server.



A database format (SQLite, PostgreSQL) provides query performance and indexing at the cost of requiring a specific runtime to read the file. For an accountability ledger — a file that may need to be read years in the future by parties unfamiliar with the original system — a self-describing text format is the correct choice.



### 16.6  Why Ten Signing Fields and Not More



Every field in the signing surface was included because it is necessary to bind the signature to the context in which the record was produced:



| Field        | Why it must be signed |

|---           |---                    |

| `gef_version`| Prevents downgrade attacks across protocol versions |

| `record_id`  | Binds the signature to this specific record, not a copy |

| `record_type`| Prevents relabeling an `intent` as an `execution` |

| `agent_id`   | Prevents attribution transfer to another agent |

| `signer_public_key` | Binds the key identity into the signed content |

| `sequence`   | Prevents reordering within a ledger |

| `nonce`      | Prevents replay across ledgers |

| `timestamp`  | Prevents temporal manipulation of the record |

| `causal_hash` | Binds the record to its specific predecessor |

| `payload`    | Binds the actual content of the action |



No field is present for decoration. No field is absent to save space.



### 16.7  Why Apache 2.0 and Not MIT or GPL



Apache 2.0 provides:



- **Patent termination clause:** contributors implicitly license any relevant patents under the Apache grant. This is important for cryptographic software where patent risk is non-trivial.

- **Explicit contribution terms** via the Contributor License Agreement framework.

- **Compatibility** with most open-source licenses.

- **Institutional familiarity:** Apache 2.0 is the default license for many enterprise-grade open-source projects (Kubernetes, TensorFlow, Apache Kafka).



MIT lacks the patent clause. GPL requires derivative works to be open-sourced, which creates friction for institutional adopters who wish to integrate GEF into proprietary systems.



***



## 17. References



**\[RFC 2119]**

Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119, March 1997.

https://www.rfc-editor.org/rfc/rfc2119



**\[RFC 4648]**

Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006.

https://www.rfc-editor.org/rfc/rfc4648



**\[RFC 8032]**

Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.

https://www.rfc-editor.org/rfc/rfc8032



**\[RFC 8785]**

Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.

https://www.rfc-editor.org/rfc/rfc8785



**\[FIPS-180-4]**

National Institute of Standards and Technology, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

https://doi.org/10.6028/NIST.FIPS.180-4



**\[JSONL]**

JSON Lines format specification. https://jsonlines.org



***



## Appendix A: Field Quick Reference



| Field        | Type   | Length / Format | Required | In Signing Surface |

|---           |---     |---       |---|---|

| `gef_version`| string | `"1.0"`  | ✅ | ✅ |

| `record_id`  | string | non-empty, UUID v4 recommended | ✅ | ✅ |

| `record_type`| string | see registry | ✅ | ✅ |

| `agent_id`   | string | non-empty | ✅ | ✅ |

| `signer_public_key` | string | 64 lowercase hex chars | ✅ | ✅ |

| `sequence`   | integer | ≥ 0, monotonically increasing | ✅ | ✅ |

| `nonce`      | string | 32 lowercase hex chars (128-bit CSPRNG) | ✅ | ✅ |

| `timestamp`  | string | `YYYY-MM-DDTHH:mm:ss.sssZ` (UTC) | ✅ | ✅ |

| `causal_hash`| string | 64 lowercase hex chars | ✅ | ✅ |

| `payload`    | object | JSON object `{}` | ✅ | ✅ |

| `signature`  | string | ~86 base64url chars, no padding | ✅ | ❌ |



***



## Appendix B: Violation Type Registry



| Violation Type | Phase   | Description |

|---             |---      |---          |

| `schema`       | Phase 1 | Entry fails schema validation (missing field, wrong type, invalid format, unregistered record type, version mismatch) |

| `sequence_gap` | Phase 1 | `sequence` is not exactly `prev.sequence + 1` |

| `chain_break`  | Phase 1 | `causal_hash` does not match `SHA-256(JCS(prev.signing_surface))` |

| `invalid_signature` | Phase 2 | `Ed25519.Verify` returns False for this entry's signature |



***



## Appendix C: Record Type Registry and Governance



### Registered Record Types



| Value      | Semantic | Introduced | Status |

|---         |---       |---         |---     |

| `execution`| Agent executed an action or tool call | GEF-SPEC-1.0 | Stable |

| `intent`   | Agent declared intent to act | GEF-SPEC-1.0 | Stable |

| `result`   | Agent recorded outcome of a prior action | GEF-SPEC-1.0 | Stable |

| `failure`  | Agent recorded a failure or error | GEF-SPEC-1.0 | Stable |



### Governance Model



**The registry is centralized and specification-controlled.**

The authoritative record type registry is this appendix. A `record_type`

value is valid if and only if it appears in the registered record types

table of the `gef_version` claimed by the envelope.



**Adding a new record type.**

A new record type may be added by:



1\. Opening a proposal in the GEF specification repository: 

&nbsp;  `https://github.com/viruswami5511/guardclaw`

2\. Providing: the proposed string value, its semantic definition, the use case it addresses, and evidence that existing record types do not cover the use case.

3\. Review and approval by the specification maintainers.

4\. Publication as a minor version amendment to the specification (`GEF-SPEC-1.Y`).



**Application-specific record types are NOT permitted.**

An implementation MUST NOT use `record_type` values not registered in the specification version it claims via `gef_version`. This ensures that any verifier can look up an unknown `record_type` in the specification rather than treating it as an opaque string.



**Rationale.**

A centralized, controlled registry ensures any two parties using GEF can exchange ledgers and interpret every record type without bilateral negotiation. This is the same model used by IANA for HTTP status codes, MIME types, and TLS cipher suites.



**Namespaced experimental record types (informative).**

During development, implementations MAY use record types prefixed with `x-` (e.g., `"x-audit"`, `"x-observe"`). These are not registered, not portable, and will be rejected by standard verifiers. They are intended only for prototyping before a formal registration proposal is submitted.



***



## Appendix D: Signing Surface Field Order (Informative)



RFC 8785 JCS sorts JSON object keys by Unicode code point order of their UTF-8 encoded byte sequences. For the ten fields of the GEF signing surface, the canonical sorted order is:



```

&nbsp;1.  agent_id            (a-g-e-n-t-_-i-d)

&nbsp;2.  causal_hash         (c-a-u-s-a-l-_-h)

&nbsp;3.  gef_version         (g-e-f-_-v)

&nbsp;4.  nonce               (n-o-n-c-e)

&nbsp;5.  payload             (p-a-y-l-o-a-d)

&nbsp;6.  record_id           (r-e-c-o-r-d-_-i-d)

&nbsp;7.  record_type         (r-e-c-o-r-d-_-t-y-p-e)

&nbsp;8.  sequence            (s-e-q)

&nbsp;9.  signer_public_key   (s-i-g-n-e-r)

10\.  timestamp           (t-i-m-e)

```



`record_id` sorts before `record_type` because after the common prefix `record_`, the next character of `record_id` is `i` (0x69) and of `record_type` is `t` (0x74), and `i` < `t`.



`sequence` sorts before `signer_public_key` because `e` (0x65) < `i` (0x69) at the second character.



**This ordering is informative.** Implementations MUST NOT hard-code this order in their JSON construction — they MUST pass the object to a conformant JCS library and allow the library to sort.



***



***



*GEF Protocol Specification — Version 1.0*

*© 2026 GuardClaw Protocol Team*

*Licensed under the Apache License, Version 2.0*

*Repository: https://github.com/viruswami5511/guardclaw*

*Published: 2026-02-27*
