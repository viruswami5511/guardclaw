\# GuardClaw Phase 1: Execution Inevitability



\*\*Status:\*\* COMPLETE  

\*\*Date:\*\* 2026-02-08  

\*\*Version:\*\* 1.0-phase1



---



\## Overview



Phase 1 establishes GuardClaw's \*\*execution wrapper\*\* - the structural choke point that makes accountability provable.



\### What Phase 1 Delivers



✅ \*\*Execution Wrapper\*\* - Structural choke point for all tool execution  

✅ \*\*Guaranteed Settlement\*\* - Runs even on execution failure  

✅ \*\*Append-Only Ledger\*\* - All actions recorded immutably  

✅ \*\*Five Invariant Tests\*\* - Proves structural correctness  

✅ \*\*Two Demos\*\* - Shows wrapper in action



---



\## Key Principle



> \*\*"Execution inevitability comes before cryptographic perfection."\*\*



A perfect signature on a bypassable system is worthless. Phase 1 makes the wrapper \*\*structurally mandatory\*\*.



---



\## Architecture



Agent → @guardclaw.protect → Wrapper

↓

1\. Authorize (PolicyEngine)

↓

2\. Execute (ToolExecutor)

↓

3\. Generate Receipt (always)

↓

4\. Settle (SettlementEngine, always)

↓

5\. Log to Ledger (append-only)



text



\### Critical Invariants



1\. \*\*Cannot bypass wrapper\*\* - No execution without accountability

2\. \*\*Settlement always runs\*\* - Even on failure

3\. \*\*Ledger is append-only\*\* - Cannot delete history

4\. \*\*Reload preserves integrity\*\* - All data survives

5\. \*\*Executor cannot be forged\*\* - User code cannot fake receipts



---



\## Running Phase 1



\### Setup



```bash

cd "C:\\Users\\rohan\\OneDrive\\Desktop\\GuardClaw New"



\# Install in development mode

pip install -e .



\# Run all tests

pytest tests/ -v

Run Invariant Tests

bash

\# These MUST all pass

pytest tests/integration/test\_invariants.py -v

Expected output:



text

test\_invariants.py::TestInvariant1CannotBypassWrapper::... PASSED

test\_invariants.py::TestInvariant2SettlementAlwaysRuns::... PASSED

test\_invariants.py::TestInvariant3LedgerAppendOnly::... PASSED

test\_invariants.py::TestInvariant4LedgerIntegrityPreserved::... PASSED

test\_invariants.py::TestInvariant5ExecutorCannotBeForged::... PASSED

Run Demos

File Operations Demo:



bash

python -m guardclaw.demos.file\_operations

Dangerous Actions Demo:



bash

python -m guardclaw.demos.dangerous\_actions

What Phase 1 Does NOT Include

Phase 1 intentionally excludes:



❌ Ed25519 (uses HMAC) - See CRYPTO\_STATUS.md

❌ Canonical encoding spec

❌ Offline verifier CLI

❌ Framework integration

❌ Auditor documentation



These come in Phase 2+.



Success Criteria

Phase 1 is complete when:



✅ All 5 invariant tests pass



✅ Both demos run successfully



✅ Ledger survives save/reload



✅ Settlement runs on failure



✅ Executor is private



Next Steps

Phase 2: Cryptographic Hardening



Upgrade to Ed25519



Canonical serialization spec



Offline verification core



Hash binding (proof ↔ receipt)



Technical Notes

Trust Boundaries

PolicyEngine - Trusted (makes decisions)



ToolExecutor - Untrusted (executes actions)



SettlementEngine - Trusted, policy-blind (reconciles facts)



Ledger - Source of truth (immutable)



Failure Handling

python

\# Settlement ALWAYS runs

try:

&nbsp;   result = executor.execute(...)

finally:

&nbsp;   settlement = settle(proof, receipt)  # Always called

This prevents attackers from avoiding audit by triggering errors.



Documentation

Phase 1 README (this file)



Crypto Status - Phase 1 crypto limitations



Protocol Spec - Full protocol documentation



Main README - Project overview



Phase 1 establishes the foundation. All future work builds on this.



text



\*\*\*



\### \*\*FILE 12: `docs/phase1/CRYPTO\_STATUS.md`\*\*



\*\*Location:\*\* `docs/phase1/CRYPTO\_STATUS.md`



```markdown

\# Phase 1 Cryptographic Status



\*\*Status:\*\* INTENTIONAL LIMITATION  

\*\*Date:\*\* 2026-02-08



---



\## ⚠️ IMPORTANT: Phase 1 Crypto is Weak by Design



Phase 1 uses \*\*HMAC (symmetric keys)\*\* for signing.



\*\*This is intentionally weak\*\* and exists ONLY to validate control flow, not to provide production security.



---



\## Known Limitations



\### 1. Symmetric Keys (HMAC)

\- \*\*Problem:\*\* Single secret shared between components

\- \*\*Risk:\*\* If key leaks, entire system is compromised

\- \*\*Status:\*\* Acceptable for Phase 1 only



\### 2. No Offline Verification

\- \*\*Problem:\*\* Receipts cannot be verified without GuardClaw

\- \*\*Risk:\*\* Makes us a vendor, not a protocol

\- \*\*Status:\*\* Fixed in Phase 2



\### 3. No Non-Repudiation

\- \*\*Problem:\*\* Any component with the key can forge any signature

\- \*\*Risk:\*\* Cannot prove who signed what

\- \*\*Status:\*\* Fixed in Phase 2 with Ed25519



\### 4. Key Storage

\- \*\*Problem:\*\* Keys stored in plain files

\- \*\*Risk:\*\* Easy to compromise

\- \*\*Status:\*\* HSM integration deferred to Phase 2+



---



\## When This Is Fixed



\*\*Phase 2: Cryptographic Hardening\*\*



Phase 2 will upgrade to:

\- ✅ \*\*Ed25519\*\* (asymmetric signatures)

\- ✅ \*\*Public/private key separation\*\*

\- ✅ \*\*Offline verification\*\* (public key only)

\- ✅ \*\*Canonical encoding\*\* (deterministic hashing)

\- ✅ \*\*Hash binding\*\* (proof ↔ receipt)



---



\## Why Phase 1 Uses Weak Crypto



\*\*GPT's guidance:\*\*



> "Execution inevitability comes before cryptographic perfection. A perfect signature on a bypassable system is worthless."



\*\*The priorities:\*\*



1\. \*\*First:\*\* Make bypass structurally impossible (✅ Phase 1)

2\. \*\*Second:\*\* Make it cryptographically sound (Phase 2)

3\. \*\*Third:\*\* Make it adversarially tested (Phase 3)



---



\## Production Use



\*\*DO NOT USE PHASE 1 IN PRODUCTION.\*\*



Phase 1 is for:

\- ✅ Validating architecture

\- ✅ Testing invariants

\- ✅ Proving control flow

\- ✅ Building demos



Phase 1 is NOT for:

\- ❌ Production deployments

\- ❌ Real accountability

\- ❌ Auditor verification

\- ❌ Compliance requirements



---



\## Honest Communication



\*\*To auditors:\*\*



"Phase 1 crypto is intentionally weak. We prioritized proving the execution wrapper is structurally sound before investing in production-grade cryptography."



\*\*This honesty signals:\*\*

\- ✅ Architectural maturity

\- ✅ Realistic expectations

\- ✅ Proper sequencing



\*\*Not:\*\*

\- ❌ Recklessness

\- ❌ Ignorance

\- ❌ False confidence



---



\## Timeline



\- \*\*Phase 1\*\* (Current): Weak crypto, strong architecture

\- \*\*Phase 2\*\* (Week 3-4): Production crypto

\- \*\*Phase 3\*\* (Week 5): Adversarial testing

\- \*\*Phase 4\*\* (Week 6-7): Auditor tooling



---



\*\*Phase 1 crypto is a temporary scaffold, not the foundation.\*\*



🎉 PHASE 1 COMPLETE - ALL FILES PROVIDED

Files Created: 12

✅ guardclaw/runtime/\_\_init\_\_.py



✅ guardclaw/runtime/context.py



✅ guardclaw/runtime/executor.py



✅ guardclaw/core/wrapper.py



✅ guardclaw/demos/\_\_init\_\_.py



✅ guardclaw/demos/file\_operations.py



✅ guardclaw/demos/dangerous\_actions.py



✅ tests/unit/test\_wrapper.py



✅ tests/integration/test\_invariants.py



✅ tests/integration/test\_execution\_flow.py



✅ docs/phase1/README.md



✅ docs/phase1/CRYPTO\_STATUS.md

