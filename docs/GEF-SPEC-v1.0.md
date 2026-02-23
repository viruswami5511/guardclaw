

\# GuardClaw Evidence Format (GEF) Specification v1.0



\*\*Document:\*\* GEF-SPEC-v1.0

\*\*Status:\*\* Draft

\*\*Authors:\*\* GuardClaw Project

\*\*Created:\*\* 2026-02-23

\*\*Repository:\*\* https://github.com/viruswami5511/guardclaw



---



\## Abstract



This document defines the GuardClaw Evidence Format (GEF), a protocol for producing cryptographically non-repudiable records of actions taken by autonomous AI agents. GEF provides per-action signing, replay-bound causality chaining, and offline verifiability without trust in any runtime or logging  infrastructure. 



---



\## 1. Terminology



The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.



\*\*Action Record:\*\* A single signed evidence unit representing one discrete agent action.



\*\*Subject:\*\* The agent identity on whose behalf an action is recorded. 



\*\*Ledger:\*\* An ordered, append-only sequence of Action Records sharing a genesis context.



\*\*Genesis Record:\*\* The root record that initialises a Ledger and binds its identity parameters.



\*\*Causal Hash:\*\* A SHA-256 digest of the Execution Envelope of the immediately preceding Action Record, binding records into a chain.



\*\*Replay-Bound Nonce:\*\* A per-subject monotonically increasing unsigned 64-bit integer encoded as a base-10 string without leading zeros (except the value "0"). Each new record from a subject MUST carry a nonce strictly greater than the last observed nonce for that subject. Gaps are permitted. Contiguity is not required.



\*\*Execution Envelope:\*\* The canonicalised byte payload over which the signature is computed, produced using the JSON Canonicalization Scheme (JCS) as defined in RFC 8785.



\*\*Content Commitment:\*\* A SHA-256 digest substituting raw content when redaction is required.



---



\## 2. Design Goals



GEF is designed to satisfy the following properties:



1\. \*\*Non-repudiation.\*\* Each Action Record is signed at the moment of execution, before any result is returned to the caller. No post-hoc fabrication is possible without invalidating the signature.



2\. \*\*Replay resistance.\*\* Each Action Record includes a subject-scoped nonce. A verifier MUST reject any record whose nonce does not exceed the last verified nonce for that subject.



3\. \*\*Causal integrity.\*\* Each Action Record (except the Genesis Record) includes the Causal Hash of its predecessor. A verifier MUST reject any record whose Causal Hash does not match.



4\. \*\*Offline verifiability.\*\* Verification MUST be possible using only the Ledger file and the signing public key. No network access, runtime connection, or trusted third party is required.



5\. \*\*Redaction compatibility.\*\* Sensitive content MAY be replaced with a Content Commitment without invalidating the signature or weakening any of the above properties.



---



\## 3. Action Record Schema



An Action Record is a JSON object. All fields marked REQUIRED MUST be present. All string fields MUST be non-empty. Field order in the serialised form is defined in Section 5 (Canonicalisation).



Payload schemas defined in Section 3.3 specify minimum required fields. Implementations MAY include additional fields within the `payload` object. Unknown fields MUST NOT cause verification failure.



```json

{

&nbsp; "gef\_version":    "1.0",

&nbsp; "record\_id":      "<uuid-v4>",

&nbsp; "record\_type":    "<string>",

&nbsp; "subject\_id":     "<string>",

&nbsp; "ledger\_id":      "<uuid-v4>",

&nbsp; "sequence":       <integer>,

&nbsp; "timestamp\_utc":  "<ISO-8601-UTC>",

&nbsp; "causal\_hash":    "<hex-sha256 | null>",

&nbsp; "nonce":          "<uint64-decimal-string>",

&nbsp; "payload":        { },

&nbsp; "content\_mode":   "raw | hash-only",

&nbsp; "schema\_version": "1.0",

&nbsp; "signature":      "<base64url-ed25519>"

}

```



\### 3.1 Field Definitions



| Field            | Required | Type   | Description |

|-------           |----------|------  |-------------|

| `gef\_version`    | REQUIRED | string | MUST be `"1.0"` for this version |

| `record\_id`      | REQUIRED | string | UUID v4, unique per record |

| `record\_type`    | REQUIRED | string | See Section 3.2 |

| `subject\_id`     | REQUIRED | string | Stable identifier of the acting agent |

| `ledger\_id`      | REQUIRED | string | UUID v4 of the containing Ledger |

| `sequence`       | REQUIRED | integer| Zero-based, monotonically increasing per Ledger |

| `timestamp\_utc`  | REQUIRED | string | See Section 3.4 |

| `causal\_hash`    | REQUIRED | string or null | SHA-256 hex of previous record's Execution Envelope; `null` only for Genesis Record |

| `nonce`          | REQUIRED | string | Unsigned 64-bit integer encoded as base-10 string without leading zeros (except `"0"`). MUST be strictly greater than the last observed nonce for the same `subject\_id` when compared as integers. Gaps are permitted. |

| `payload`        | REQUIRED | object | Action-type-specific data; see Section 3.3 |

| `content\_mode`   | REQUIRED | string | `"raw"` or `"hash-only"`; see Section 6 |

| `schema\_version` | REQUIRED | string | MUST be `"1.0"` |

| `signature`      | REQUIRED | string | Base64url-encoded Ed25519 signature over Execution Envelope |



\### 3.2 Record Types



The following `record\_type` values are defined in this version:



| Value       | Meaning |

|---          |---      |

| `genesis`   | Ledger initialisation record |

| `intent`    | Agent receives instruction or goal |

| `action`    | Agent executes a discrete operation |

| `tool\_call` | Agent invokes an external tool or API |

| `result`    | Agent emits an output or return value |

| `approval`  | Human-in-the-loop approval or rejection |

| `tombstone` | Agent session terminates |



Implementations MAY define additional `record\_type` values using a reverse-domain prefix (e.g. `com.example.custom\_type`). Unknown types MUST NOT cause verification failure; they MUST be treated as opaque payloads.



\### 3.3 Payload Schemas



\#### `genesis`

```json

{

&nbsp; "ledger\_name":  "<string>",

&nbsp; "created\_by":   "<string>",

&nbsp; "purpose":      "<string>",

&nbsp; "public\_key":   "<base64url-ed25519-public-key>"

}

```



\#### `action` / `tool\_call`

```json

{

&nbsp; "action\_type":  "<string>",

&nbsp; "parameters":   { },

&nbsp; "target":       "<string | null>"

}

```



\#### `intent`

```json

{

&nbsp; "instruction":  "<string>"

}

```



\#### `result`

```json

{

&nbsp; "status":       "success | failure | partial",

&nbsp; "output":       "<any | content-commitment>",

&nbsp; "duration\_ms":  <integer>

}

```



\#### `approval`

```json

{

&nbsp; "approver\_id":   "<string>",

&nbsp; "decision":      "approved | rejected",

&nbsp; "ref\_record\_id": "<uuid-v4>",

&nbsp; "reason":        "<string | null>"

}

```



\#### `tombstone`

```json

{

&nbsp; "reason":  "<string | null>"

}

```



\### 3.4 Timestamp Format



`timestamp\_utc` MUST conform to the following constraints:



\- MUST be expressed in UTC

\- MUST end with the literal character `Z`

\- MUST include exactly three fractional second digits

\- MUST NOT include timezone offset notation

\- MUST NOT omit the fractional seconds component



Valid example:   `2026-02-23T16:30:00.000Z`

Invalid example: `2026-02-23T22:00:00+05:30`

Invalid example: `2026-02-23T16:30:00Z`



Note: Standard library methods such as Python's

`datetime.utcnow().isoformat()` do not guarantee three fractional digits when trailing digits are zero. Implementations MUST enforce the three-digit constraint explicitly.



---



\## 4. Genesis Record



A Ledger MUST begin with exactly one Genesis Record. The Genesis Record:



\- MUST have `record\_type` of `"genesis"`

\- MUST have `sequence` of `0`

\- MUST have `causal\_hash` of `null`

\- MUST include the signing public key in `payload.public\_key`

\- MUST be self-signed with the corresponding private key



All subsequent records in the Ledger MUST be verifiable against the

public key declared in the Genesis Record.



\### 4.1 Key Binding Rules



\- A Ledger is bound to exactly one signing keypair, declared in the Genesis Record.

\- All records in the Ledger MUST be signed with the private key corresponding to `payload.public\_key` in the Genesis Record.

\- Multiple `subject\_id` values MAY share one Ledger and one keypair.

\- `subject\_id` is a logical agent identifier and MUST NOT be assumed to equal any key fingerprint or cryptographic identity.

\- If a key rotation is required, a new Ledger MUST be created with a new Genesis Record per Section 4.3.



\### 4.2 Genesis Self-Signature



The Genesis Record is self-signed. Before trusting `payload.public\_key`, a verifier MUST:



1\. Construct the Execution Envelope of the Genesis Record per Section 5.

2\. Verify the Genesis Record's Ed25519 signature using `payload.public\_key`.

3\. Reject the Ledger if verification fails.



An unverified Genesis Record MUST NOT be used as a trust anchor. This prevents substitution of an attacker-controlled public key via a malicious Genesis Record.



\### 4.3 Key Rotation



When key rotation is required, a new Ledger MUST be created with a new Genesis Record. The final record of the previous Ledger MUST be a tombstone. The new Genesis Record payload SHOULD include the previous Ledger's final Execution Envelope hash as a cross-reference. Rotation ceremony details are deferred to v1.1 after production validation.



---



\## 5. Canonicalisation



The Execution Envelope is the canonical byte sequence over which the Ed25519 signature is computed.



\### 5.1 Procedure



The Execution Envelope MUST be produced by applying the JSON Canonicalization Scheme (JCS) as defined in RFC 8785 to the Action Record object with the `signature` field removed.



Implementations MUST use a conforming JCS library. Implementations MUST NOT implement custom JSON canonicalization. The resulting UTF-8 byte sequence is the Execution Envelope.



\### 5.2 Rationale



JCS resolves Unicode normalisation, character escaping, and numeric serialisation ambiguities that arise across language runtimes and JSON parsers. Mandating RFC 8785 ensures cross-language, cross-implementation verification correctness without implementer error.



---



\## 6. Content Commitment Mode



When `content\_mode` is `"hash-only"`, sensitive payload fields MUST be replaced with their SHA-256 digest prior to signing.



\### 6.1 Procedure



1\. Identify fields in `payload` that contain sensitive content.

2\. For each such field, replace the value with:



```json

{

&nbsp; "commitment": "<sha256-hex-of-original-utf8-value>",

&nbsp; "algorithm":  "sha256"

}

```



3\. Set `content\_mode` to `"hash-only"`.

4\. Compute signature over the redacted record as normal.



\### 6.2 Properties



\- The signature remains valid and verifiable.

\- The original content cannot be reconstructed from the commitment.

\- A verifier can confirm that a known value matches a commitment without storing the original.

\- This mode satisfies data minimisation requirements under GDPR, HIPAA, and India DPDP Act 2023.



---



\## 7. Signature Computation



GuardClaw MUST use Ed25519 as defined in RFC 8032.



\### 7.1 Signing Procedure



1\. Construct the Execution Envelope per Section 5.

2\. Sign the Execution Envelope bytes using the subject's Ed25519 private key.

3\. Encode the 64-byte signature as base64url with no padding, per RFC 4648 §5.

4\. Set the `signature` field to this value.



The signature MUST be computed before control returns to the caller of the action API. Signing after the action result has been returned to the caller violates the non-repudiation guarantee defined in Section 2.



\### 7.2 Key Requirements



\- Each subject SHOULD have a dedicated Ed25519 keypair.

\- Private keys MUST NOT be stored in the Ledger.

\- In Ghost Mode (ephemeral operation), keys MAY be generated at session start and discarded at session end. Verification of ephemeral-key ledgers requires the public key to have been recorded in the Genesis Record.

\- In Strict Mode (production operation), private keys SHOULD be stored in an HSM or KMS.



---



\## 8. Chain Invariant



\### 8.1 Definition



For any record `R\[n]` where `n > 0`:



```

R\[n].causal\_hash == SHA-256( ExecutionEnvelope( R\[n-1] ) )

```



This invariant binds each record to its predecessor, forming a tamper-evident chain.



\### 8.2 Properties



\- Modifying any record in the chain invalidates all subsequent

&nbsp; `causal\_hash` values.

\- The chain can be verified in O(n) time with O(1) space.

\- Chain verification is independent of signature verification;

&nbsp; both MUST pass.



\### 8.3 Concurrency Constraint



GEF v1.0 defines a strictly linear chain. Ledger appends MUST be sequential. Implementations supporting concurrent agent execution MUST serialise record appends through a single writer before signing.



Concurrent execution patterns that require multiple simultaneous causal parents (Directed Acyclic Graph structures) are not supported in GEF v1.0. Support for DAG-structured evidence chains is deferred to a future version.



---



\## 9. Replay-Bound Invariant



\### 9.1 Definition



For any two records `R\[a]` and `R\[b]` with the same `subject\_id`, where `R\[a]` was observed before `R\[b]`:



```

integer(R\[b].nonce) > integer(R\[a].nonce)

```



Nonce values MUST be compared as integers.

A verifier MUST reject any record where the integer value of nonce is not strictly greater than the last verified nonce for that `subject\_id`.



Gaps in nonce values are permitted and MUST NOT cause verification failure. Contiguity is not required.



\### 9.2 Rationale



Monotonic ordering without contiguity requirement provides replay protection while surviving agent restarts, concurrent execution, crash recovery, and multi-process deployments. Strict +1 enforcement would produce operationally brittle implementations without strengthening the replay guarantee.



Coordination of nonce uniqueness across distributed processes is an implementation responsibility. Implementations MUST document their nonce coordination strategy.



---



\## 10. Verification Procedure



A conforming verifier MUST execute the following steps in order. Failure at any step MUST result in rejection of the Ledger.



```

1\. PARSE    — Deserialise each record. Reject malformed JSON.



2\. GENESIS  — Confirm record is type "genesis" with

&nbsp;              sequence=0 and causal\_hash=null.

&nbsp;              Extract candidate public key from

&nbsp;              payload.public\_key.

&nbsp;              Verify the Genesis Record's Ed25519 signature

&nbsp;              using this candidate public key.

&nbsp;              If signature verification fails, REJECT.

&nbsp;              Only after successful verification, accept

&nbsp;              payload.public\_key as the trust anchor for

&nbsp;              all subsequent records.



3\. SEQUENCE — For each record\[n], confirm sequence == n.



4\. CHAIN    — For each record\[n] where n > 0, confirm:

&nbsp;              record\[n].causal\_hash ==

&nbsp;              SHA-256(ExecutionEnvelope(record\[n-1]))



5\. NONCE    — For each record, confirm integer(nonce) is

&nbsp;              strictly greater than the last verified nonce

&nbsp;              for that subject\_id. Gaps are permitted.



6\. SIGN     — For each record, recompute ExecutionEnvelope

&nbsp;              per Section 5 (RFC 8785), verify Ed25519

&nbsp;              signature against the public key from the

&nbsp;              Genesis Record.



7\. ACCEPT   — If all steps pass, the Ledger is VALID.

```



A verifier MAY report per-step results for diagnostic purposes. A verifier MUST NOT report a Ledger as VALID unless all seven steps pass.



---



\## 11. Cryptographic Primitives



All cryptographic operations in GEF v1.0 use the following algorithms. Implementations MUST NOT substitute alternative algorithms without defining a new `gef\_version`.



| Primitive        | Algorithm | Reference   |

|------------------|-----------|-------------|

| Hash function    | SHA-256   | FIPS 180-4  |

| Signatures       | Ed25519   | RFC 8032    |

| Encoding         | Base64url | RFC 4648 §5 |

| Canonicalisation | JCS       | RFC 8785    |

| Random source    | CSPRNG    | OS-provided |



---



\## 12. Security Considerations



\### 12.1 Signing at Execution Time



Signatures MUST be computed before the action result is returned to the caller. Signing after result delivery creates a window in which the action description can be altered. This is the primary architectural distinction between GEF and session-close attestation models.



\### 12.2 Threat: Log Fabrication



An agent that fabricates log entries after the fact cannot produce valid signatures without the private key. If a compromised agent attempts to rewrite its history, signature verification will fail for all fabricated records.



\### 12.3 Threat: Replay Attack



A captured valid record cannot be replayed into a different Ledger or position due to the Replay-Bound Invariant (Section 9) and the Causal Hash binding (Section 8).



\### 12.4 Threat: Key Compromise



If a signing key is compromised, an adversary can produce valid-appearing records. Key compromise does not retroactively invalidate previously signed records. Implementations SHOULD rotate keys per Section 4.3 and SHOULD anchor ledger state to an external timestamping authority before performing rotation.



\### 12.5 Threat: Clock Manipulation



System-generated `timestamp\_utc` values reflect operator-asserted time. An adversary with system access may manipulate the system clock to generate records with false timestamps. GEF signatures do not cryptographically bind records to external wall-clock time.



For legal or regulatory contexts where authoritative timestamps are required, implementations SHOULD submit periodic Ledger state hashes to a trusted timestamping authority (TSA) as defined in RFC 3161. Without TSA anchoring, `timestamp\_utc` values prove relative ordering within the Ledger only, not authoritative wall-clock time.



\### 12.6 Threat: Tail Truncation



GEF v1.0 provides tamper evidence for the records present within a Ledger. It does not prevent a malicious operator from truncating the Ledger by deleting records from the end of the chain. A truncated Ledger passes all seven verification steps against its remaining records; truncation is not detectable by a verifier operating on the Ledger alone.



Mitigation: To prove Ledger completeness at a specific point in time, implementations SHOULD periodically publish the chain head hash (SHA-256 of the latest Execution Envelope) to an external transparency log or trusted timestamping service. This produces external evidence of how many records existed at a given time and makes tail truncation detectable by comparison.



Resistance to tail truncation via external anchoring is a Level 4 property outside the scope of GEF v1.0.



\### 12.7 Out of Scope



GEF does not address: network transport security, access control to Ledger storage, or the correctness of agent behaviour. GEF provides evidence of what was recorded. It does not provide evidence of what was not recorded.



---



\## 13. Versioning



\- The `gef\_version` field identifies the spec version that governs the record.

\- This document defines `gef\_version: "1.0"`.

\- Future versions MUST increment the version string.

\- A verifier encountering an unknown `gef\_version` SHOULD warn and MAY reject.

\- The core signing and chain invariants defined in this version are considered stable. Breaking changes require a major version increment.



---



\## 14. Reserved Fields



The following field names are reserved for future GEF versions and MUST NOT be used for application-defined extensions:



`gef\_extensions`, `gef\_proof`, `gef\_anchor`, `gef\_policy`, `gef\_root`



Application-defined extensions MUST use a reverse-domain prefix in

field names (e.g. `com.example.custom\_field`).



---



\## 15. IANA Considerations



This document has no IANA actions.



Future versions of this specification may request registration of:



\- Media type: `application/gef+json`

\- URI scheme: `gef://`



---



\## 16. Normative References



```

\[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

&nbsp;          https://www.rfc-editor.org/rfc/rfc2119



\[RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.

&nbsp;          https://www.rfc-editor.org/rfc/rfc8032



\[RFC4648]  Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006.

&nbsp;          https://www.rfc-editor.org/rfc/rfc4648



\[RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.

&nbsp;          https://www.rfc-editor.org/rfc/rfc8785



\[FIPS180]  National Institute of Standards and Technology, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

&nbsp;          https://doi.org/10.6028/NIST.FIPS.180-4

```



---



\## 17. Informative References



```

\[RFC6962]  Laurie, B., Langley, A., and E. Kasper, "Certificate Transparency", RFC 6962, June 2013.

&nbsp;          https://www.rfc-editor.org/rfc/rfc6962



\[RFC3161]  Adams, C., et al., "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)", RFC 3161, August 2001.

&nbsp;          https://www.rfc-editor.org/rfc/rfc3161



\[GDPR]     European Parliament, "General Data Protection Regulation", Regulation (EU) 2016/679, April 2016.



\[DPDP]     Government of India, "Digital Personal Data Protection Act", Act No. 22 of 2023, August 2023.

```



---



\## 18. Acknowledgments



This specification builds upon cryptographic primitives and design patterns established by the Certificate Transparency (RFC 6962), Edwards-Curve Digital Signature Algorithm (RFC 8032), and JSON Canonicalization Scheme (RFC 8785) communities. The replay-bound evidence model, per-action signing requirement, and Genesis self-signature trust establishment are original contributions of the GuardClaw project.



---



\## Appendix A — Minimal Conformance Checklist



An implementation claiming GEF v1.0 conformance MUST:



\- \[ ] Produce records matching the schema in Section 3

\- \[ ] Begin every Ledger with a Genesis Record per Section 4

\- \[ ] Verify Genesis self-signature before trusting public key per Section 4.2

\- \[ ] Apply JCS canonicalisation per RFC 8785 and Section 5 using a conforming library

\- \[ ] Sign every record with Ed25519 before returning any result

\- \[ ] Use monotonically increasing nonces per subject per Section 9

\- \[ ] Serialise concurrent appends sequentially per Section 8.3

\- \[ ] Pass all seven verification steps in Section 10

\- \[ ] Use only the cryptographic primitives listed in Section 11



---



\## Appendix B — Example Action Record



```json

{

&nbsp; "gef\_version":    "1.0",

&nbsp; "record\_id":      "a3f2c1d4-e5b6-7890-abcd-ef1234567890",

&nbsp; "record\_type":    "tool\_call",

&nbsp; "subject\_id":     "agent-prod-001",

&nbsp; "ledger\_id":      "b4e3d2c1-f6a7-8901-bcde-f01234567891",

&nbsp; "sequence":       3,

&nbsp; "timestamp\_utc":  "2026-02-23T16:30:00.000Z",

&nbsp; "causal\_hash":    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",

&nbsp; "nonce":          "3",

&nbsp; "payload": {

&nbsp;   "action\_type":  "file.delete",

&nbsp;   "parameters": {

&nbsp;     "path": "/var/logs/archive/2025-01.log"

&nbsp;   },

&nbsp;   "target":       "/var/logs/archive/2025-01.log"

&nbsp; },

&nbsp; "content\_mode":   "raw",

&nbsp; "schema\_version": "1.0",

&nbsp; "signature":      "base64url-encoded-ed25519-signature-here"

}

```



---



\## Appendix C — Example Verification Output



```

GuardClaw Ledger Verification

──────────────────────────────────────────

Ledger:   b4e3d2c1-f6a7-8901-bcde-f01234567891

Subject:  agent-prod-001

Records:  12



Step 1 — Parse         ✓ 12 records parsed

Step 2 — Genesis       ✓ Genesis record valid, self-signature verified

Step 3 — Sequence      ✓ Sequence 0–11 contiguous

Step 4 — Chain         ✓ Causal hash chain intact

Step 5 — Nonce         ✓ Replay-bound invariant satisfied

Step 6 — Signatures    ✓ All 12 signatures verified

Step 7 — Accept        ✓ Ledger is VALID



──────────────────────────────────────────

Result: VALID

```

