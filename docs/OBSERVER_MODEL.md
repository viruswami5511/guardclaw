\# GuardClaw Observer Model



\*\*Document Version:\*\* 1.0  

\*\*Protocol Version:\*\* 3.0 (Phase 5)  

\*\*Status:\*\* NORMATIVE SPECIFICATION  

\*\*Last Updated:\*\* February 10, 2026



---



\## Executive Summary



The GuardClaw Observer Model defines how runtime systems are \*\*observed (not controlled)\*\* to produce cryptographically verifiable evidence of AI agent activity.



Observers are \*\*passive\*\*, \*\*non-blocking\*\*, and \*\*framework-agnostic\*\*.  

They do not prevent actions, enforce policy, or alter execution.



> \*\*GuardClaw watches. It does not decide. It does not block.\*\*



This design intentionally prioritizes \*\*accountability, auditability, and legal defensibility\*\* over real-time enforcement.



---



\## Core Principle



\*\*Execution must never depend on GuardClaw.\*\*



If GuardClaw fails, crashes, or is removed:

\- The system continues to run

\- Evidence gaps become visible

\- Accountability is preserved via absence detection



This is a deliberate safety and legal property.



---



\## What Is an Observer?



\### Definition



An \*\*Observer\*\* is a passive runtime hook that records \*what happened\* without influencing \*what happens\*.



\### An Observer \*\*IS\*\*



\- ✅ Passive runtime hook  

\- ✅ Non-blocking event emitter  

\- ✅ Framework-agnostic  

\- ✅ Failure-visible  

\- ✅ Cryptographically accountable  



\### An Observer \*\*IS NOT\*\*



\- ❌ A controller  

\- ❌ A policy engine  

\- ❌ A security gate  

\- ❌ A required dependency  

\- ❌ A synchronous interceptor  



\### Separation of Concerns



| Layer | Responsibility | Blocks Execution | Failure Impact |

|-----|---------------|------------------|----------------|

| Runtime | Executes actions | N/A | System failure |

| Observer | Records facts | ❌ No | Detectable gaps |

| Emitter | Signs evidence | ❌ No | Resume on restart |

| Ledger | Stores proofs | ❌ No | Durable record |



---



\## Observation Event Types



GuardClaw defines \*\*seven\*\* canonical observation events.



\### 1. INTENT

Records declared intent \*before\* execution.



Use cases:

\- User commands

\- API requests

\- Scheduled jobs

\- System-initiated actions



Purpose: establishes \*\*what was intended\*\*.



---



\### 2. EXECUTION

Records that an action actually occurred.



Use cases:

\- Tool invocation

\- Side-effect execution

\- External API calls



Purpose: establishes \*\*what happened\*\*.



---



\### 3. RESULT

Records successful completion.



Use cases:

\- Tool output

\- Action completion

\- State mutation success



Purpose: establishes \*\*what the outcome was\*\*.



---



\### 4. FAILURE

Records unsuccessful execution.



Use cases:

\- Exceptions

\- Timeouts

\- Permission errors

\- Resource exhaustion



Purpose: establishes \*\*what failed and why\*\*.



---



\### 5. DELEGATION

Records task delegation between agents.



Use cases:

\- Multi-agent workflows

\- Capability escalation

\- Subtask spawning



Purpose: establishes \*\*who delegated to whom\*\*.



---



\### 6. HEARTBEAT

Records observer liveness.



Purpose:

\- Proves observer was operational

\- Enables detection of silent failure

\- Establishes continuity of observation



---



\### 7. TOMBSTONE

Records \*\*explicit absence\*\*.



Use cases:

\- Observer shutdown

\- Planned maintenance

\- Agent revocation

\- Expected event did not occur



Purpose: establishes \*\*negative proof\*\*.



---



\## Passive vs Active Systems



\### Passive Observation (GuardClaw)

Action → Execution → Observation → Evidence

Characteristics:

\- No execution control

\- No blocking

\- No enforcement

\- Evidence after the fact



Advantages:

\- Zero runtime coupling

\- High reliability

\- Framework independence

\- Legally defensible



---



\### Active Control (Not GuardClaw)



Action Request → Policy Check → Block / Allow → Execution



Disadvantages:

\- Performance bottlenecks

\- Single point of failure

\- Tight coupling

\- Reduced audit trust



---



\## Observer Lifecycle



\### 1. Initialization



\*\*Ghost Mode (Development):\*\*

\- Ephemeral keys

\- Auto-generated genesis

\- Zero ceremony



\*\*Strict Mode (Production):\*\*

\- Explicit genesis

\- Registered agents

\- Enforced delegation



---



\### 2. Observation



Observers emit:

\- INTENT

\- EXECUTION

\- RESULT or FAILURE

\- DELEGATION (if applicable)



All emissions are \*\*non-blocking\*\*.



---



\### 3. Liveness



Observers emit \*\*heartbeats\*\* at fixed intervals.



If heartbeats stop:

\- Observer failure is detectable

\- Evidence gap is explicit



---



\### 4. Shutdown



Observers emit a \*\*tombstone\*\* on clean shutdown.



This distinguishes:

\- Intentional stop

\- Unexpected crash



---



\## Failure Visibility



\### Silent Failure Is Evidence Failure



Without GuardClaw:

\- Observer crashes → undetectable

\- Logs missing → ambiguous



With GuardClaw:

\- Missing heartbeats = detectable failure

\- Tombstones = intentional absence

\- Gaps become evidence



---



\## Legal Implications



\### Non-Interference



Observers:

\- Do not alter execution

\- Do not enforce outcomes

\- Do not influence decisions



This aligns with:

\- Server logs

\- Security cameras

\- Flight data recorders



---



\### Business Records Doctrine



GuardClaw evidence satisfies standard admissibility criteria:



\- Made at or near time of event  

\- Recorded by automated system with knowledge  

\- Kept in regular course of business  

\- Generated systematically  



---



\### Negative Proof



GuardClaw can prove \*\*non-occurrence\*\*:



> “The agent did \*not\* perform action X between T1 and T2.”



Proof basis:

\- Continuous heartbeats

\- Absence of execution events

\- Explicit tombstones



---



\## Design Guarantees



\*\*Phase 5 Observer Model guarantees:\*\*



\- ✅ Non-blocking execution

\- ✅ Framework independence

\- ✅ Failure visibility

\- ✅ Cryptographic integrity

\- ✅ Verifiable gaps

\- ✅ Legal defensibility



---



\## See Also



\- `ACCOUNTABILITY\_LAG.md`

\- `DEV\_MODE\_vs\_PROD\_MODE.md`

\- `SCOPE\_OF\_TRUTH.md`



\*\*Document Status:\*\* FINAL  

\*\*Next Review:\*\* Phase 6




