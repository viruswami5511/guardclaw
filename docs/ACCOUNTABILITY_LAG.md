\# Accountability Lag



\*\*Document Version:\*\* 1.0  

\*\*Protocol Version:\*\* 3.0 (Phase 5)  

\*\*Status:\*\* NORMATIVE SPECIFICATION  

\*\*Last Updated:\*\* February 10, 2026



---



\## Executive Summary



\*\*Accountability Lag\*\* is the time between when an action executes and when cryptographic evidence of that action is signed.



This lag is:

\- \*\*Intentional\*\*

\- \*\*Measured\*\*

\- \*\*Recorded\*\*

\- \*\*Disclosed\*\*



> \*\*Execution is never delayed for evidence. Evidence follows execution.\*\*



---



\## Definition



Accountability Lag is defined as: accountability\_lag = signed\_at − execution\_timestamp

Where:

\- `execution\_timestamp` = when the action occurred

\- `signed\_at` = when evidence was cryptographically signed



Lag is expressed in milliseconds.



---



\## Why Lag Exists



\### 1. Performance



Cryptographic signing is expensive.  

Blocking execution would degrade system performance and reliability.



GuardClaw prioritizes \*\*execution continuity\*\*.



---



\### 2. Reliability



Synchronous evidence creation creates a single point of failure.



Asynchronous signing ensures:

\- Execution always completes

\- Evidence resumes after crashes

\- Failures are visible, not silent



---



\### 3. Developer Experience



GuardClaw is designed to:

> “Work in 2 minutes at 2 AM.”



Blocking execution breaks this promise.



---



\### 4. Real-World Precedent



Many accepted systems operate with lag:



| System | Lag | Legally Valid |

|------|----|---------------|

| Server logs | Seconds | Yes |

| Security cameras | Seconds | Yes |

| Financial settlement | Hours–Days | Yes |

| Medical records | Hours | Yes |



GuardClaw aligns with these norms.



---



\## Lag Breakdown



GuardClaw tracks multiple timestamps:



\- `execution\_timestamp`

\- `observation\_timestamp`

\- `emission\_timestamp`

\- `signed\_at`



This allows precise diagnosis of where delay occurred.



Example timeline:14:37:00.000  Action executed 14:37:00.001  Observed 14:37:00.005  Queued 14:37:00.123  Signed

Total accountability lag: \*\*123 ms\*\*



---



\## Lag vs Validity



\### Critical Rule



\*\*Lag does not affect cryptographic validity.\*\*



Signatures depend on:

\- Content

\- Key

\- Algorithm



They do \*\*not\*\* depend on immediacy.



---



\### Transparency Principle



Disclosed lag is admissible.  

Hidden lag is suspicious.



GuardClaw discloses lag \*\*explicitly in every record\*\*.



---



\## Legal Implications



Courts require:

\- Accuracy

\- Integrity

\- Regularity

\- Transparency



They do \*\*not\*\* require instant signing.



GuardClaw satisfies admissibility standards by:

\- Recording actual execution time

\- Preserving chain of custody

\- Disclosing all delays



---



\## Crash Recovery



If a system crashes before signing:

\- Events remain in write-ahead buffer

\- Signed later on restart

\- Lag increases

\- Cause is visible



Large lag = operational signal, not invalid evidence.



---



\## Operational Guidance



\### Default Targets (Strict Mode)



\- P95 lag: < 2 seconds

\- Warning: > 10 seconds

\- Error: > 60 seconds



\### Ghost Mode



\- Lag tolerated

\- No enforcement

\- Focus on usability



---



\## Key Takeaways



\- Lag is intentional

\- Lag is measured

\- Lag is disclosed

\- Lag ≠ invalidity

\- Lag reflects reality



---



\*\*Validity Formula:\*\*



Validity = Cryptographic Integrity + Contextual Completeness Validity ≠ Instantaneous Signing



---



\*\*Document Status:\*\* FINAL  

\*\*Next Review:\*\* Phase 6






