\# GuardClaw Phase 3 Protocol: Trust \& Authority Hardening



\*\*Version:\*\* 3.0.0  

\*\*Status:\*\* Complete  

\*\*Date:\*\* February 10, 2026



---



\## Executive Summary



\*\*Phase 3 Mission:\*\* Upgrade GuardClaw from "cryptographically correct" to "institutionally credible."



> \*\*Phase 2 proves integrity. Phase 3 proves authority.\*\*



Phase 3 establishes \*\*who\*\* authorized actions, \*\*why\*\* they happened, \*\*what\*\* context influenced decisions, and creates auditable proof of \*\*what didn't happen\*\*.



---



\## Phase 3 Pillars



\### 1️⃣ Genesis \& Identity Binding



\*\*Problem:\*\* A court/regulator can argue: "Who authorized this agent or key? This ledger could be self-created."



\*\*Solution:\*\*

\- Every ledger MUST start with a `GenesisRecord` (Event 0)

\- Genesis establishes:

&nbsp; - Root authority (who can delegate)

&nbsp; - Ledger purpose and jurisdiction

&nbsp; - Creation timestamp and creator identity

&nbsp; - Organizational context



\*\*Records:\*\*

\- `GenesisRecord` - Foundational record signed by root authority

\- `AgentRegistration` - Agent authorization with capabilities

\- `KeyDelegation` - Authority delegation chain



\*\*Benefit:\*\* You can prove who created the agent and who authorized it.



---



\### 2️⃣ Non-Repudiation at Organizational Level



\*\*Problem:\*\* Companies can claim: "That agent didn't represent our corporate intent."



\*\*Solution:\*\*

\- `AuthorizationProof` now includes:

&nbsp; - `policy\_anchor\_hash` - Immutable reference to policy

&nbsp; - `approver\_key\_id` - Who "turned the key"

&nbsp; - `organizational\_context` - Org metadata



\*\*Benefit:\*\* Organizations cannot disown actions after the fact.



---



\### 3️⃣ Context \& Causality ("Why did this happen?")



\*\*Problem:\*\* Phase 2 proves what happened, not why.



\*\*Solution:\*\*

\- Every action tracks:

&nbsp; - `trigger\_hash` - What input caused this action (privacy-safe hash)

&nbsp; - `context\_manifest\_hash` - What data was used for decision

&nbsp; - `intent\_reference` - Link to user prompt/command



\*\*Records:\*\*

\- `TriggerContext` - What caused the action

\- `ContextManifest` - What data influenced the decision

\- `IntentReference` - Link to original user intent



\*\*Benefit:\*\* Distinguish:

\- User instruction vs AI hallucination

\- External manipulation vs internal failure

\- Expected behavior vs anomaly



---



\### 4️⃣ Negative Proof \& Liveness



\*\*Problem:\*\* Courts hate missing data. "I don't know" is not legally defensible.



\*\*Solution:\*\*

\- `HeartbeatRecord` - Periodic proof of system liveness

\- `TombstoneRecord` - Explicit marker for expected-but-missing records

\- Sequence numbers prevent gaps



\*\*Records:\*\*

\- `HeartbeatRecord` - Proof system is operational

\- `TombstoneRecord` - Explicit failure marker



\*\*Benefit:\*\* "I know that I don't know, and here's why" becomes provable.



---



\### 5️⃣ Chain of Custody \& Admin Actions



\*\*Problem:\*\* The system audits itself — circular trust.



\*\*Solution:\*\*

\- `AdminActionRecord` logs all privileged operations:

&nbsp; - Key rotations

&nbsp; - Configuration changes

&nbsp; - System upgrades

&nbsp; - Access control modifications



\*\*Separation of Duties:\*\*

\- \*\*Issuer\*\* (policy engine)

\- \*\*Executor\*\* (runtime)

\- \*\*Settler\*\* (settlement engine)

\- \*\*Administrator\*\* (system operations)



\*\*Benefit:\*\* Tampering becomes detectable even by admins.



---



\## Phase 3 Data Models



\### GenesisRecord



```python

{

&nbsp;   "genesis\_id": "genesis-uuid",

&nbsp;   "ledger\_name": "Production Ledger",

&nbsp;   "created\_at": "2026-02-10T00:00:00Z",

&nbsp;   "created\_by": "CTO <cto@example.com>",

&nbsp;   "root\_key\_id": "root\_public\_key\_hex",

&nbsp;   "purpose": "AI Agent Authorization System",

&nbsp;   "schema\_version": "3.0.0",

&nbsp;   "jurisdiction": "US-CA",

&nbsp;   "organizational\_context": {

&nbsp;       "organization": "Example Corp",

&nbsp;       "compliance": \["SOC2", "GDPR"]

&nbsp;   },

&nbsp;   "signature": "ed25519\_signature"

}

AgentRegistration

python

{

&nbsp;   "agent\_id": "agent-001",

&nbsp;   "registration\_id": "agent-reg-uuid",

&nbsp;   "registered\_by": "admin@example.com",

&nbsp;   "registered\_at": "2026-02-10T00:00:00Z",

&nbsp;   "delegated\_from\_key": "parent\_key\_hex",

&nbsp;   "agent\_key\_id": "agent\_key\_hex",

&nbsp;   "capabilities": \["file:read", "file:write", "file:delete"],

&nbsp;   "valid\_from": "2026-02-10T00:00:00Z",

&nbsp;   "valid\_until": "2027-02-10T00:00:00Z",

&nbsp;   "purpose": "File management agent",

&nbsp;   "signature": "ed25519\_signature"

}

KeyDelegation

python

{

&nbsp;   "delegation\_id": "delegation-uuid",

&nbsp;   "parent\_key\_id": "parent\_key\_hex",

&nbsp;   "child\_key\_id": "child\_key\_hex",

&nbsp;   "delegated\_by": "admin@example.com",

&nbsp;   "delegated\_at": "2026-02-10T00:00:00Z",

&nbsp;   "scope": {

&nbsp;       "actions": \["read", "write"],

&nbsp;       "resources": \["database"]

&nbsp;   },

&nbsp;   "valid\_from": "2026-02-10T00:00:00Z",

&nbsp;   "valid\_until": null,

&nbsp;   "signature": "ed25519\_signature"

}

AuthorizationProof (Phase 3 Extended)

python

{

&nbsp;   # Phase 2 fields (unchanged)

&nbsp;   "proof\_id": "proof-abc123",

&nbsp;   "action": {...},

&nbsp;   "decision": "approved",

&nbsp;   "reason": "...",

&nbsp;   "policy\_version": "1.0.0",

&nbsp;   "issued\_at": "2026-02-10T00:00:00Z",

&nbsp;   "expires\_at": "2026-02-10T01:00:00Z",

&nbsp;   "issuer": "policy-engine",

&nbsp;   "signature": "ed25519\_signature",

&nbsp;   

&nbsp;   # Phase 3 additions

&nbsp;   "policy\_anchor\_hash": "sha256\_of\_policy",

&nbsp;   "approver\_key\_id": "approver\_key\_hex",

&nbsp;   "trigger\_context": {

&nbsp;       "trigger\_id": "trigger-uuid",

&nbsp;       "trigger\_type": "user\_command",

&nbsp;       "trigger\_hash": "sha256\_of\_trigger",

&nbsp;       "triggered\_at": "2026-02-10T00:00:00Z",

&nbsp;       "source": "web-ui"

&nbsp;   },

&nbsp;   "intent\_reference": {

&nbsp;       "intent\_id": "intent-uuid",

&nbsp;       "intent\_type": "user\_prompt",

&nbsp;       "intent\_hash": "sha256\_of\_intent",

&nbsp;       "recorded\_at": "2026-02-10T00:00:00Z"

&nbsp;   },

&nbsp;   "organizational\_context": {

&nbsp;       "cost\_center": "engineering",

&nbsp;       "compliance\_tags": \["data\_retention"]

&nbsp;   }

}

ExecutionReceipt (Phase 3 Extended)

python

{

&nbsp;   # Phase 2 fields (unchanged)

&nbsp;   "receipt\_id": "receipt-abc123",

&nbsp;   "proof\_id": "proof-abc123",

&nbsp;   "executed\_at": "2026-02-10T00:00:00Z",

&nbsp;   "executor": "executor",

&nbsp;   "success": true,

&nbsp;   "result": {...},

&nbsp;   "proof\_hash": "sha256\_of\_proof",

&nbsp;   "signature": "ed25519\_signature",

&nbsp;   

&nbsp;   # Phase 3 additions

&nbsp;   "context\_manifest\_hash": "sha256\_of\_manifest",

&nbsp;   "execution\_duration\_ms": 2340

}

SettlementRecord (Phase 3 Extended)

python

{

&nbsp;   # Phase 2 fields (unchanged)

&nbsp;   "settlement\_id": "settlement-abc123",

&nbsp;   "proof\_id": "proof-abc123",

&nbsp;   "receipt\_id": "receipt-abc123",

&nbsp;   "settled\_at": "2026-02-10T00:00:00Z",

&nbsp;   "settler": "settler",

&nbsp;   "verification\_result": "verified",

&nbsp;   "verification\_details": {...},

&nbsp;   "proof\_hash": "sha256\_of\_proof",

&nbsp;   "receipt\_hash": "sha256\_of\_receipt",

&nbsp;   "signature": "ed25519\_signature",

&nbsp;   

&nbsp;   # Phase 3 additions

&nbsp;   "verification\_trace": {

&nbsp;       "proof\_signature\_verified": true,

&nbsp;       "receipt\_signature\_verified": true,

&nbsp;       "hash\_binding\_verified": true,

&nbsp;       "authority\_chain\_verified": true,

&nbsp;       "timestamp": "2026-02-10T00:00:00Z"

&nbsp;   }

}

HeartbeatRecord

python

{

&nbsp;   "heartbeat\_id": "heartbeat-000001-uuid",

&nbsp;   "sequence\_number": 1,

&nbsp;   "timestamp": "2026-02-10T00:00:00Z",

&nbsp;   "system\_state": "operational",

&nbsp;   "expected\_next\_heartbeat": "2026-02-10T01:00:00Z",

&nbsp;   "previous\_heartbeat\_id": null,

&nbsp;   "signature": "ed25519\_signature"

}

TombstoneRecord

python

{

&nbsp;   "tombstone\_id": "tombstone-uuid",

&nbsp;   "expected\_record\_type": "authorization",

&nbsp;   "expected\_record\_id": "proof-12345",

&nbsp;   "expected\_at": "2026-02-10T00:00:00Z",

&nbsp;   "failure\_reason": "Policy denied",

&nbsp;   "failure\_category": "denied",

&nbsp;   "detected\_at": "2026-02-10T00:00:05Z",

&nbsp;   "context": {

&nbsp;       "policy\_rule": "rule-003",

&nbsp;       "violated\_constraint": "..."

&nbsp;   },

&nbsp;   "signature": "ed25519\_signature"

}

AdminActionRecord

python

{

&nbsp;   "action\_id": "admin-uuid",

&nbsp;   "admin\_key\_id": "admin\_key\_hex",

&nbsp;   "admin\_identity": "admin@example.com",

&nbsp;   "action\_type": "key\_rotation",

&nbsp;   "action\_details": {

&nbsp;       "old\_key\_id": "key-001",

&nbsp;       "new\_key\_id": "key-002"

&nbsp;   },

&nbsp;   "performed\_at": "2026-02-10T00:00:00Z",

&nbsp;   "affected\_components": \["policy\_engine", "executor"],

&nbsp;   "signature": "ed25519\_signature"

}

Authority Chain Verification

Phase 3 enables complete authority chain verification:



text

Genesis (Root Authority)

&nbsp;   ↓

KeyDelegation (Optional, multi-level)

&nbsp;   ↓

AgentRegistration (Agent + Capabilities)

&nbsp;   ↓

AuthorizationProof (Policy Decision)

&nbsp;   ↓

ExecutionReceipt (Action Execution)

&nbsp;   ↓

SettlementRecord (Verification)

Verification Checks:



✅ Genesis signature valid (root authority)



✅ Agent registration valid at time of action



✅ Delegation chain valid (if multi-level)



✅ Agent has capability for action type



✅ Proof signed by authorized key



✅ Policy anchor present and valid



✅ Trigger context present



✅ Intent reference present



✅ Phase 2 cryptographic integrity (signatures, hashes)



Legal \& Regulatory Alignment

Phase 3 makes GuardClaw outputs structurally ready for:



Business Records Exception: Records made in regular course of business



Self-Authenticating Evidence: Records that prove their own authenticity



Chain of Custody: Complete provenance from root authority to action



Non-Repudiation: Organizations cannot disown actions



Note: Phase 3 provides structural readiness, not legal certification. Consult legal counsel for specific jurisdictions.







