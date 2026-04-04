# GuardClaw Evidence Format — Advanced Extensions Draft

**Document:** GEF-SPEC-v1.1-draft  
**Status:** Experimental Draft — Not implemented in GuardClaw v0.7.x  
**Supersedes:** Nothing. This document extends, not replaces, GEF-SPEC-1.0.  
**Authors:** GuardClaw Project  
**Repository:** https://github.com/viruswami/guardclaw

---

> **⚠ Implementation Notice**
>
> This document explores advanced extensions to GEF-SPEC-1.0. None of the
> features described here are implemented in the current GuardClaw release (v0.7.x).
>
> Extensions covered in this draft:
> - Subject-scoped replay invariants (monotonic nonce model)
> - Ledger identity separation (`ledger_id`)
> - Content commitment mode (privacy-preserving payload redaction)
> - Richer record taxonomy (`approval`, `tombstone`, `tool_call`)
> - Key rotation ceremony
> - Tail anchoring
>
> **Do not implement against this document for production systems.**  
> For the normative, shipping specification, see `GEF-SPEC-1.0.md`.

---

## Abstract

This document defines proposed extensions to the GuardClaw Evidence Format (GEF)
beyond the currently stable GEF-SPEC-1.0 baseline. These extensions are motivated
by real production requirements encountered in multi-agent systems,
compliance-sensitive deployments, and long-lived audit ledger scenarios.

GEF-SPEC-1.0 is a narrow, correct, currently shipped protocol.
GEF-SPEC-v1.1 adds layered capabilities without breaking GEF-SPEC-1.0 invariants.

The guiding principle is the same as in GEF-SPEC-1.0:

> **GuardClaw proves what was recorded. It does not decide what should have happened.**

---

## 1. Terminology

Key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "MAY" are as defined in RFC 2119.

**Subject:** The logical agent identity on whose behalf an action is recorded.
A single ledger MAY contain records from multiple subjects.

**Ledger:** An ordered, append-only sequence of `ExecutionEnvelope` records sharing
a genesis context and a **single signing keypair**. All records in a ledger MUST
be signed by the same key declared in the genesis record.

**Ledger ID:** A stable UUID v4 binding records to a named ledger instance,
enabling cross-ledger reference and multi-ledger deployments.

**Subject-Scoped Nonce:** A monotonically increasing unsigned 64-bit integer,
scoped per `subject_id`, providing stronger replay resistance than
random-nonce uniqueness alone.

**Content Commitment:** A SHA-256 digest substituting a sensitive payload field
for privacy-preserving record emission. The signature remains valid over the
committed form.

**Execution Envelope:** The canonicalized byte payload over which the Ed25519
signature is computed, produced using RFC 8785 JCS, excluding `signature`.

**Causal Hash:** SHA-256 of the Execution Envelope of the immediately preceding
record. Binds records into a tamper-evident hash chain.

---

## 2. Design Goals for v1.1

GEF-SPEC-v1.1 extends GEF-SPEC-1.0 to satisfy the following additional requirements:

1. **Stronger replay resistance.**
   Subject-scoped monotonic nonces provide a total ordering guarantee per subject
   that random-nonce uniqueness cannot provide.

2. **Multi-ledger deployability.**
   `ledger_id` enables records to be unambiguously attributed to a specific
   ledger instance in systems running multiple concurrent ledgers.

3. **Privacy-preserving compliance.**
   Content commitment mode allows records to satisfy GDPR, HIPAA, and India DPDP
   Act 2023 data minimization requirements without breaking signature validity.

4. **Richer audit taxonomy.**
   A richer record type set enables complete lifecycle coverage for complex
   multi-step agent workflows including human-in-the-loop approval gates.

5. **Key lifecycle management.**
   Explicit key rotation procedures with cross-ledger continuity proofs.

6. **Tail anchoring.**
   External timestamping and transparency log integration to make tail truncation
   detectable beyond the ledger boundary.

---

## 3. Extended Envelope Schema

GEF-SPEC-v1.1 adds the following optional fields to the GEF-SPEC-1.0
`ExecutionEnvelope`. All GEF-SPEC-1.0 fields and invariants remain fully binding.

```jsonc
{
  // --- GEF-SPEC-1.0 fields (unchanged, all invariants apply) ---
  "gef_version":       "1.1",
  "record_id":         "<uuid-v4>",
  "record_type":       "<string>",
  "agent_id":          "<string>",
  "signer_public_key": "<base64url-ed25519-pubkey>",
  "sequence":          41,
  "nonce":             "<string>",
  "timestamp":         "2026-04-03T14:30:00.000Z",
  "causal_hash":       "<hex-sha256>",
  "payload":           { },
  "signature":         "<base64url-ed25519-signature>",

  // --- GEF-SPEC-v1.1 extensions (all OPTIONAL) ---
  "subject_id":        "<string>",         // logical sub-agent identity
  "ledger_id":         "<uuid-v4>",        // stable ledger binding
  "content_mode":      "raw | hash-only",  // defaults to "raw" when absent
  "schema_version":    "1.1"               // informational
}
```

### 3.1 Field Additions

**`subject_id`**
- OPTIONAL.
- Stable identifier for a logical sub-agent within a ledger.
- When present, subject-scoped monotonic nonce semantics MUST apply (see Section 5).
- Multiple `subject_id` values MAY share one ledger and keypair.
- MUST NOT be assumed to equal any cryptographic key fingerprint.

**`ledger_id`**
- OPTIONAL.
- UUID v4 binding the record to a named ledger instance.
- Records within a ledger SHOULD share a consistent `ledger_id`.

**`content_mode`**
- OPTIONAL; defaults to `"raw"` when absent.
- When `"hash-only"`, sensitive payload fields MUST be replaced with
  SHA-256 content commitments before signing (see Section 7).

**`schema_version`**
- OPTIONAL informational field indicating the extended schema variant in use.

---

## 4. Extended Record Types

GEF-SPEC-v1.1 adds the following `record_type` values to those defined in GEF-SPEC-1.0:

| Value       | Meaning                                          |
|-------------|--------------------------------------------------|
| `tool_call` | Agent invokes an external tool, API, or service  |
| `approval`  | Human-in-the-loop decision (approved / rejected) |
| `tombstone` | Explicit session or ledger termination           |

GEF-SPEC-1.0 types (`genesis`, `intent`, `execution`, `result`, `failure`)
are unchanged and remain the minimal required set for GEF-SPEC-1.0 conformance.

### 4.1 Forward Compatibility Rule

A GEF-SPEC-1.0 verifier operating in **forward-compatible mode** MUST ignore
unknown `record_type` values (such as `tool_call`, `approval`, `tombstone`)
and MUST still enforce all cryptographic invariants (signature, chain, nonce).

A GEF-SPEC-1.0 verifier operating in **strict mode** MUST reject unknown
`record_type` values and MUST clearly indicate that a newer spec version
may be required.

This rule resolves the strict/forward-compatible tension between specs.
Verifier mode MUST be documented and explicitly chosen by the operator.

### 4.2 Extended Payload Schemas

#### `tool_call`
```jsonc
{
  "action_type":  "<string>",        // REQUIRED — tool or operation identifier
  "parameters":   { },               // REQUIRED — input parameters
  "target":       "<string | null>"  // OPTIONAL — resource or endpoint target
}
```

#### `approval`
```jsonc
{
  "approver_id":   "<string>",              // REQUIRED — approving party identity
  "decision":      "approved | rejected",   // REQUIRED
  "ref_record_id": "<uuid-v4>",             // REQUIRED — record being decided on
  "reason":        "<string | null>"        // OPTIONAL
}
```

#### `tombstone`
```jsonc
{
  "reason": "<string | null>"  // OPTIONAL — termination reason
}
```

---

## 5. Nonce Semantics in GEF-SPEC-v1.1

GEF-SPEC-v1.1 defines two nonce modes. The mode in effect for a given record
is determined by the presence or absence of `subject_id`. Mixed semantics
within the same `subject_id` group MUST cause verification failure.

### 5.1 Mode A — GEF-SPEC-1.0 Semantics (subject_id absent)

When `subject_id` is absent from a record:

- `nonce` MUST be cryptographically random.
- `nonce` MUST be unique within the ledger.
- Duplicate nonce MUST cause `DUPLICATE_NONCE` failure.

This is identical to GEF-SPEC-1.0 behavior.

### 5.2 Mode B — Subject-Scoped Monotonic Semantics (subject_id present)

When `subject_id` is present in a record:

- `nonce` MUST be a monotonically increasing unsigned 64-bit integer,
  encoded as a decimal string without leading zeros (except the value `"0"`).
- For any two records `R[a]` and `R[b]` with the same `subject_id`, where
  `R[a]` appears before `R[b]` in the ledger:

```
integer( R[b].nonce ) > integer( R[a].nonce )
```

- Gaps in nonce values are permitted. Contiguity is not required.
- Violation of this invariant MUST cause `SUBJECT_NONCE_VIOLATION` failure.

This model provides a total ordering guarantee per subject that random-nonce
uniqueness alone cannot provide.

### 5.3 Mixed Semantics Rule

- If any record in the ledger includes `subject_id`, all records with the
  same `subject_id` MUST use monotonic nonce semantics.
- Records without `subject_id` in the same ledger MUST use GEF-SPEC-1.0
  random nonce semantics.
- A verifier MUST detect and reject any ledger where nonce semantics are
  inconsistently applied within a `subject_id` group.
- Failure code: `NONCE_MODE_INCONSISTENCY`

### 5.4 Nonce Coordination

Coordination of nonce uniqueness across distributed processes is an
implementation responsibility. Implementations using subject-scoped monotonic
nonces MUST document their nonce coordination strategy.

---

## 6. Ledger Identity and Multi-Ledger Deployments

### 6.1 Ledger Binding

When `ledger_id` is present, all records within a logical ledger SHOULD share
the same `ledger_id` value. The genesis record SHOULD include `ledger_id` to
establish the binding at chain root.

### 6.2 Cross-Ledger Reference

When a new ledger is created as a continuation of a previous ledger (e.g.,
after key rotation), the new genesis record payload SHOULD include:

```jsonc
{
  "previous_ledger_id":  "<uuid-v4>",
  "previous_chain_head": "<hex-sha256>",
  "previous_chain_seq":  "<integer>"
}
```

This creates a verifiable cross-ledger continuity chain without mutating the
hash-chain invariant of either ledger.

---

## 7. Content Commitment Mode

Content commitment mode enables records to be emitted with sensitive fields
replaced by their cryptographic hash, satisfying data minimization requirements
while preserving signature validity.

### 7.1 Procedure

1. Identify fields in `payload` containing sensitive content.
2. For each such field, replace the value with:

```jsonc
{
  "commitment": "<sha256-hex-of-original-utf8-value>",
  "algorithm":  "sha256"
}
```

3. Set `content_mode` to `"hash-only"`.
4. Compute the signature over the redacted envelope as normal per GEF-SPEC-1.0 Section 5.

### 7.2 Properties

- The signature is valid and verifiable over the committed form.
- The original content cannot be reconstructed from the commitment alone.
- A verifier can confirm that a known value matches a commitment without storing the original.
- Signatures over committed payloads are indistinguishable from signatures
  over raw payloads from a verification standpoint.

### 7.3 Compliance Scope

This mode is designed to satisfy data minimization requirements under:

- GDPR (EU) 2016/679, Article 5(1)(c)
- HIPAA (US) 45 CFR §164.514
- India DPDP Act 2023

Compliance determination is the responsibility of the implementing system.
GuardClaw provides the cryptographic mechanism; it does not provide legal advice.

---

## 8. Key Rotation

Key rotation in GEF-SPEC-v1.1 is handled by ledger succession, not in-band
key replacement.

### 8.1 Rotation Procedure

1. Emit a `tombstone` record as the final record of the current ledger.
2. Create a new ledger with a new genesis record and a new keypair.
3. The new genesis record SHOULD include a cross-reference payload per Section 6.2.
4. All verifiers MUST apply the key declared in each ledger's genesis record
   to that ledger's records only.

### 8.2 Rotation Safety

Key compromise does not retroactively invalidate previously signed records.
External timestamping anchors (RFC 3161) applied before rotation can prove
the integrity of pre-rotation records independently.

> **Rotation window warning:** Between tombstone emission and new genesis creation,
> the ledger is in a rotation window. Events during this window cannot be
> chain-linked to either ledger. Implementations MUST minimize this window.

---

## 9. Tail Anchoring

GEF-SPEC-1.0 does not prevent tail truncation of a ledger.
GEF-SPEC-v1.1 defines a recommended anchoring practice to make truncation
externally detectable.

### 9.1 Chain Head Publication

Implementations SHOULD periodically publish the chain head to an external
transparency log or timestamping authority:

```
chain_head_hash = SHA256( canonical_signing_surface( last_entry ) )
chain_head_sequence = last_entry.sequence
```


### 9.2 Anchoring Methods

Acceptable anchoring methods include:

- **RFC 3161 TSA** — Trusted timestamping authority. Cryptographic time binding.
- **Git commit hash** — Chain head published into a public repository commit.
- **Certificate Transparency log** — RFC 6962-style public append-only log entry.

Any method producing a publicly verifiable commitment to a specific
`(chain_head_hash, chain_head_sequence, timestamp)` triple is acceptable.

### 9.3 Truncation Detection

A verifier comparing the current chain head against a published anchor can
detect whether records have been removed since the anchor was established.

> Tail truncation resistance via external anchoring is a Level 4 optional
> capability, outside the scope of GEF-SPEC-1.0.

---

## 10. Extended Verification Procedure

When processing a ledger containing v1.1 extensions, verifiers MUST first
successfully complete all GEF-SPEC-1.0 verification steps.

Only after GEF-SPEC-1.0 validation passes MAY the following v1.1 checks be applied:

| Step | Check | Failure Code |
|------|-------|--------------|
| 8 | **Signer Consistency** — The `signer_public_key` MUST be identical across all records in the ledger. If any record contains a different `signer_public_key` than the genesis record, verification MUST fail. | `SIGNER_MISMATCH` |
| 9 | **Subject Nonce** — For each `subject_id` group: confirm `integer(nonce)` is strictly greater than the last verified nonce for that `subject_id`. Gaps permitted. | `SUBJECT_NONCE_VIOLATION` |
| 10 | **Nonce Mode** — Confirm all records apply consistent nonce semantics within each `subject_id` group. | `NONCE_MODE_INCONSISTENCY` |
| 11 | **Ledger Binding** — If `ledger_id` is present, confirm it is consistent across all records. | `LEDGER_ID_MISMATCH` |
| 12 | **Content Mode** — If `content_mode` is `"hash-only"`, confirm sensitive payload fields contain valid commitment objects and verify signature over committed form. | `INVALID_COMMITMENT` |
| 13 | **Accept** — If all GEF-SPEC-1.0 steps and all applicable v1.1 steps pass, the ledger is VALID under GEF-SPEC-v1.1. | — |

A verifier completing only GEF-SPEC-1.0 steps remains a valid GEF-SPEC-1.0
verifier. GEF-SPEC-v1.1 steps are strictly additive and MUST NOT be evaluated
before GEF-SPEC-1.0 validation completes successfully.

---

## 11. Cryptographic Primitives

All GEF-SPEC-1.0 cryptographic primitives apply unchanged. No new algorithms
are introduced in GEF-SPEC-v1.1.

| Primitive        | Algorithm | Reference    |
|------------------|-----------|--------------|
| Hash function    | SHA-256   | FIPS 180-4   |
| Signatures       | Ed25519   | RFC 8032     |
| Encoding         | Base64url | RFC 4648 §5  |
| Canonicalization | JCS       | RFC 8785     |
| Random source    | CSPRNG    | OS-provided  |

---

## 12. Compatibility With GEF-SPEC-1.0

GEF-SPEC-v1.1 is a **strict superset** of GEF-SPEC-1.0.

| Property                        | GEF-SPEC-1.0 | GEF-SPEC-v1.1 |
|---------------------------------|:------------:|:-------------:|
| `ExecutionEnvelope` core schema | ✓ normative  | ✓ unchanged   |
| `GENESIS_HASH` fixed value      | ✓ normative  | ✓ unchanged   |
| Ed25519 + JCS signing           | ✓ normative  | ✓ unchanged   |
| Hash chain + sequence           | ✓ normative  | ✓ unchanged   |
| Random nonce + duplicate check  | ✓ normative  | ✓ unchanged   |
| Signer consistency enforcement  | ✓ normative  | ✓ unchanged   |
| Subject-scoped monotonic nonce  | ✗            | OPTIONAL      |
| `ledger_id` binding             | ✗            | OPTIONAL      |
| Content commitment mode         | ✗            | OPTIONAL      |
| Extended record types           | ✗            | OPTIONAL      |
| Key rotation ceremony           | ✗            | defined       |
| Tail anchoring guidance         | ✗            | defined       |

A GEF-SPEC-1.0 verifier in forward-compatible mode can read a GEF-SPEC-v1.1
ledger and verify all GEF-SPEC-1.0 invariants correctly.
Unknown extension fields MUST be ignored by GEF-SPEC-1.0 verifiers in
forward-compatible mode.
Unknown fields MUST cause failure in strict mode.

---

## 13. Security Considerations

All security considerations in GEF-SPEC-1.0 apply without modification.

Additional considerations for v1.1 extensions:

- **Signer identity continuity:** A ledger bound to a single `signer_public_key`
  provides a clear identity boundary. Any attempt to introduce a second key
  into a ledger is detectable as `SIGNER_MISMATCH`. Key transitions MUST
  be handled via the key rotation ceremony (Section 8), not by changing
  `signer_public_key` mid-ledger.

- **Subject-scoped nonce coordination:** The monotonic nonce invariant
  requires a coordination mechanism in multi-process deployments to prevent
  races. Implementations MUST document their nonce coordination strategy.

- **Content commitment irreversibility:** Committed payload fields cannot be
  recovered from the ledger. Implementations MUST maintain secure out-of-band
  storage of original values if recovery is operationally required.

- **Key rotation window:** Between tombstone emission and new genesis creation,
  the ledger is in a rotation window. Events during this window cannot be
  chain-linked to either ledger. Implementations MUST minimize this window.

- **Anchor publication lag:** Tail anchoring provides truncation detectability
  only for records that existed at the time of the last anchor. Records appended
  after the last anchor remain unanchored until the next publication.

---

## 14. Versioning

- `gef_version: "1.1"` identifies a record governed by this extended schema.
- Verifiers encountering `gef_version: "1.1"` SHOULD apply GEF-SPEC-v1.1
  rules if available, and MUST apply GEF-SPEC-1.0 rules as a minimum baseline.
- All breaking changes require a major version increment.

---

## 15. Reserved Fields

All reserved fields from GEF-SPEC-1.0 apply.

Additional reserved names for future use:

`gef_dag_parents`, `gef_anchor_ref`, `gef_rotation_proof`, `gef_subject_root`

Application-defined extensions MUST use a reverse-domain prefix
(e.g., `com.example.custom_field`).

---

## 16. Normative References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs", RFC 2119, March 1997.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "EdDSA", RFC 8032, January 2017.
- **[RFC4648]** Josefsson, S., "Base64 Data Encodings", RFC 4648, October 2006.
- **[RFC8785]** Rundgren, A. et al., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- **[RFC3161]** Adams, C. et al., "Internet X.509 PKI Time-Stamp Protocol", RFC 3161, August 2001.
- **[FIPS180]** NIST, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

## 17. Informative References

- **[RFC6962]** Laurie, B. et al., "Certificate Transparency", RFC 6962, June 2013.
- **[GDPR]** European Parliament, Regulation (EU) 2016/679, April 2016.
- **[DPDP]** Government of India, DPDP Act No. 22 of 2023, August 2023.

---

## Appendix A — v1.1 Conformance Checklist

An implementation claiming GEF-SPEC-v1.1 conformance MUST first satisfy all
GEF-SPEC-1.0 conformance requirements, then additionally:

- [ ] Complete all GEF-SPEC-1.0 verification steps before applying any v1.1 checks
- [ ] Reject any ledger where `signer_public_key` differs from the genesis record key
- [ ] Correctly emit and verify `subject_id`-scoped monotonic nonces when present
- [ ] Reject records where the subject-scoped nonce invariant is violated
- [ ] Reject ledgers where nonce semantics are inconsistently applied within a `subject_id` group
- [ ] Maintain consistent `ledger_id` across all records in a ledger when used
- [ ] Correctly produce and verify content commitment payloads
- [ ] Emit a `tombstone` as the final record before key rotation
- [ ] Include a cross-ledger continuity reference in new genesis records after rotation
- [ ] Publish chain head anchors to an external source at configurable intervals

---

## Appendix B — Example: Extended Record (tool_call + content commitment)

```jsonc
{
  "gef_version":       "1.1",
  "record_id":         "d4e5f6a7-b8c9-4d0e-9f1a-2b3c4d5e6f7a",
  "record_type":       "tool_call",
  "agent_id":          "agent-prod-002",
  "subject_id":        "workflow-7",
  "ledger_id":         "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "signer_public_key": "<base64url-ed25519-pubkey>",
  "sequence":          12,
  "nonce":             "12",
  "timestamp":         "2026-04-03T14:30:00.000Z",
  "causal_hash":       "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "payload": {
    "action_type": "database.query",
    "parameters": {
      "query": {
        "commitment": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "algorithm":  "sha256"
      }
    },
    "target": "prod-db-cluster-01"
  },
  "content_mode":   "hash-only",
  "schema_version": "1.1",
  "signature":      "<base64url-ed25519-signature>"
}
```

---

## Design Philosophy

GEF-SPEC-v1.1 does not change why GuardClaw exists.

It extends what GuardClaw can prove — from a single-agent execution record
to a multi-subject, compliance-ready, key-lifecycle-aware evidence substrate
for the most demanding production environments.

**GuardClaw proves what was recorded.**  
It does not decide what should have happened.  
It gives policy, governance, and law something cryptographically solid to stand on.