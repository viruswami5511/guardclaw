\# Genesis Loss and Recovery



\*\*Document Version:\*\* 1.0  

\*\*Protocol Version:\*\* 3.0  

\*\*Status:\*\* NORMATIVE SPECIFICATION  

\*\*Last Updated:\*\* February 10, 2026



---



\## Purpose



This document defines the consequences, detection, and recovery options for \*\*Genesis key loss\*\* in GuardClaw.



Genesis keys are the \*\*root of trust\*\*. Their loss has permanent implications.



---



\## What Is Genesis?



Genesis establishes:

\- Ledger identity

\- Root authority

\- Trust boundary



All downstream trust derives from Genesis.



---



\## Genesis Loss Scenarios



\### 1. Genesis Private Key Lost



Effects:

\- New delegations cannot be issued

\- Existing evidence remains valid

\- Ledger integrity preserved

\- Authority expansion impossible



---



\### 2. Genesis Private Key Compromised



Effects:

\- Ledger trust is broken

\- All downstream trust is suspect

\- Revocation required



---



\### 3. Genesis Public Key Lost



Effects:

\- Verification impossible

\- Evidence unverifiable

\- Ledger effectively unusable



---



\## Recovery Options



\### Option 1: No Recovery (Recommended)



Genesis loss is treated as \*\*irreversible\*\*.



Actions:

\- Ledger frozen

\- New ledger created

\- Old ledger preserved as historical record



This mirrors:

\- Certificate authority compromise

\- Root key loss in PKI systems



---



\### Option 2: Ledger Succession (Explicit)



A new genesis may reference the old ledger as historical.



Requirements:

\- Explicit declaration

\- Human governance

\- Clear discontinuity



This creates \*\*two trust domains\*\*, not one.



---



\## What Is NOT Allowed



❌ Silent key replacement  

❌ Implicit recovery  

❌ Automatic regeneration  

❌ Backdating trust  



---



\## Legal Interpretation



Genesis loss is equivalent to:

\- Loss of corporate seal

\- Loss of root certificate authority



Evidence \*\*before loss remains valid\*\*.  

Evidence \*\*after loss must use new genesis\*\*.



---



\## Operational Best Practices



\- Hardware security modules (HSM)

\- Offline backups

\- Multi-party custody

\- Explicit documentation



---



\## Summary



\- Genesis loss is visible

\- Genesis loss is serious

\- Genesis loss is not silent

\- Genesis loss does not invalidate past evidence



---



\*\*Document Status:\*\* FINAL  

\*\*Next Review:\*\* Phase 6

