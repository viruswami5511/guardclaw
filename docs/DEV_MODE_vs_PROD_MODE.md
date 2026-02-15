\# Development Mode vs Production Mode



\*\*Document Version:\*\* 1.0  

\*\*Protocol Version:\*\* 3.0 (Phase 5)  

\*\*Status:\*\* NORMATIVE SPECIFICATION  

\*\*Last Updated:\*\* February 10, 2026



---



\## Purpose



This document defines the two operational modes of GuardClaw:



\- \*\*Ghost Mode\*\* (Development)

\- \*\*Strict Mode\*\* (Production)



These modes control \*\*how strictly GuardClaw validates accountability requirements\*\*, not what GuardClaw observes.



> \*\*GuardClaw never controls execution in any mode.\*\*



---



\## Core Principle



\*\*Mode selection affects validation, not observation.\*\*



\- Observers always emit events

\- Evidence is always cryptographically signed

\- Execution is never blocked



Modes only affect \*\*how missing or invalid accountability is handled\*\*.



---



\## Mode Overview



| Property | Ghost Mode | Strict Mode |

|--------|-----------|-------------|

| Intended use | Development, testing | Production, audit |

| Genesis required | ❌ No | ✅ Yes |

| Agent registration required | ❌ No | ✅ Yes |

| Delegation enforced | ❌ No | ✅ Yes |

| Expiry enforced | ❌ No | ✅ Yes |

| Missing evidence | Warning | Hard failure |

| Keys | Ephemeral | Persistent |

| Setup time | < 2 minutes | Explicit ceremony |



---



\## Ghost Mode (Development)



\### Definition



\*\*Ghost Mode\*\* is a permissive mode designed for developer velocity.



It enables GuardClaw to work immediately without setup while still producing \*\*cryptographically valid evidence\*\*.



---



\### Properties



\- Auto-generated ephemeral root key

\- Auto-generated ephemeral agent registration

\- No delegation enforcement

\- No expiry enforcement

\- Violations produce warnings only

\- Evidence is still signed and verifiable



---



\### Explicit Guarantees



Ghost Mode \*\*DOES guarantee\*\*:



\- Cryptographic integrity

\- Event ordering

\- Evidence replay

\- Accountability lag measurement



Ghost Mode \*\*DOES NOT guarantee\*\*:



\- Complete delegation chains

\- Identity permanence

\- Audit-grade compliance



---



\### Typical Use Cases



\- Local development

\- CI pipelines

\- Prototyping

\- Learning GuardClaw

\- Debugging agent behavior



---



\### Example Initialization



```python

from guardclaw.core.modes import init\_ghost\_mode



mode\_manager = init\_ghost\_mode()

Console output:

⚠️  GUARDCLAW GHOST MODE ACTIVE

• Genesis: AUTO-GENERATED (ephemeral)

• Agent: AUTO-REGISTERED

• Evidence: CRYPTOGRAPHICALLY VALID

• Violations: WARNINGS ONLY



Strict Mode (Production)



Definition



Strict Mode enforces all accountability requirements required for production, legal, or regulatory use.

It does not increase runtime control — only validation rigor.



Properties

Explicit genesis required

Explicit agent registration required

Delegation chains enforced

Expiry and revocation enforced

Missing evidence causes failure

No ephemeral keys allowed

Explicit Guarantees



Strict Mode DOES guarantee:

Identity continuity

Delegation traceability

Temporal validity

Audit-grade completeness



Strict Mode DOES NOT guarantee:

Prevention of bad actions

Safety enforcement



Policy compliance



Example Initialization-



from guardclaw.core.modes import init\_strict\_mode



mode\_manager = init\_strict\_mode()




Console output:



✅ GUARDCLAW STRICT MODE ACTIVE

• Genesis: REQUIRED

• Agent: REQUIRED

• Delegation: ENFORCED

• Violations: HARD FAILURES



Mode Switching Rules-



Mode must be explicit

No automatic escalation

Environment variable supported




export GUARDCLAW\_MODE=strict


Programmatic override always wins.







