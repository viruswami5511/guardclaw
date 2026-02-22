\# GuardClaw Deployment Guide


**Document Version:** 1.0
**Protocol Version:** GuardClaw v0.1.x
**Status:** OPERATIONAL GUIDE
**Last Updated:** February 10, 2026


---



\## Purpose



This guide describes \*\*how to deploy GuardClaw safely and correctly\*\* in:



\- Development environments

\- Production systems

\- Regulated / high-assurance environments



This is an \*\*operations document\*\*, not a tutorial.



---



\## Deployment Philosophy



GuardClaw follows three non-negotiable principles:



1\. \*\*Observer-only\*\* — Never blocks execution

2\. \*\*Fail-loud\*\* — Absence of evidence is detectable

3\. \*\*Local-first\*\* — No SaaS dependency



> If GuardClaw fails, your system MUST continue to run — and the failure MUST be visible.



---



\## Deployment Modes



GuardClaw supports \*\*two operational modes\*\*:



| Mode | Use Case | Keys | Enforcement |

|-----|---------|------|-------------|

| \*\*Ghost Mode\*\* | Development, testing | Ephemeral | Minimal |

| \*\*Strict Mode\*\* | Production, audit | Persistent | Full |



---



\## 1️⃣ Development Deployment (Ghost Mode)



\### When to Use

\- Local development

\- CI pipelines

\- Debugging sessions

\- Early-stage experimentation



\### Characteristics

\- No persistent keys

\- No genesis ceremony

\- Zero setup

\- No recovery guarantees



\### Setup



```python

from guardclaw.core.modes import init\_ghost\_mode

from guardclaw.core.emitter import init\_global\_emitter



mode = init\_ghost\_mode()

agent\_key = mode.get\_ephemeral\_agent\_key()



emitter = init\_global\_emitter(

&nbsp;   key\_manager=agent\_key,

&nbsp;   signing\_interval\_seconds=0.1

)



Storage Layout

.guardclaw/

├── buffer/

│   ├── pending.jsonl

│   └── signed.jsonl

└── ledger/

&nbsp;   └── observations/



Operational Notes



Data is not durable

Restart = loss of keys

Replay is best-effort

DO NOT use for compliance





2️⃣ Production Deployment (Strict Mode)

When to Use



Customer-facing systems

Long-running agents

Audit or compliance use

Regulated environments





Production Architecture (Single Node)

┌──────────────────────────┐

│      Application         │

│  (Agents / Tools)        │

└──────────┬───────────────┘

&nbsp;          │ observe()

&nbsp;          ▼

┌──────────────────────────┐

│     GuardClaw Observer   │

│  (non-blocking hooks)    │

└──────────┬───────────────┘

&nbsp;          │ enqueue

&nbsp;          ▼

┌──────────────────────────┐

│   Evidence Emitter       │

│  (async signer thread)   │

└──────────┬───────────────┘

&nbsp;          │ signed JSONL

&nbsp;          ▼

┌──────────────────────────┐

│   Evidence Ledger        │

│  (append-only files)     │

└──────────────────────────┘





Step-by-Step Production Setup

Step 1: Create Directories

mkdir -p guardclaw/{keys,ledger,buffer,archive}

chmod 700 guardclaw/keys





Step 2: Generate Root (Genesis) Key

from guardclaw.core.crypto import Ed25519KeyManager



root\_key = Ed25519KeyManager.generate()

root\_key.save\_keypair(

&nbsp;   private\_key\_path="guardclaw/keys/root.key",

&nbsp;   public\_key\_path="guardclaw/keys/root.pub"

)



\# CRITICAL

chmod 600 guardclaw/keys/root.key



🔴 This key is the root of trust. Protect it.



Step 3: Create Genesis Record

from guardclaw.core.genesis import GenesisRecord



genesis = GenesisRecord.create(

&nbsp;   ledger\_name="Production GuardClaw Ledger",

&nbsp;   created\_by="security@example.com",

&nbsp;   root\_key\_manager=root\_key,

&nbsp;   purpose="AI Agent Accountability",

&nbsp;   jurisdiction="US",

)



with open("guardclaw/ledger/genesis.json", "w") as f:

&nbsp;   json.dump(genesis.to\_dict(), f, indent=2)





Step 4: Generate Agent Key

agent\_key = Ed25519KeyManager.generate()

agent\_key.save\_keypair(

&nbsp;   private\_key\_path="guardclaw/keys/agent-001.key",

&nbsp;   public\_key\_path="guardclaw/keys/agent-001.pub"

)



chmod 600 guardclaw/keys/agent-001.key




> ⚠️ AgentRegistration is planned for Level 3–4. Not available in v0.1.x.
Step 5: Register Agent

from guardclaw.core.genesis import AgentRegistration



agent = AgentRegistration.create(

&nbsp;   agent\_id="agent-001",

&nbsp;   agent\_name="Primary Production Agent",

&nbsp;   registered\_by="security@example.com",

&nbsp;   delegating\_key\_manager=root\_key,

&nbsp;   agent\_key\_manager=agent\_key,

&nbsp;   capabilities=\["file:read", "file:write"], 

&nbsp;   valid\_from="2026-02-10T00:00:00Z",

&nbsp;   valid\_until="2027-02-10T00:00:00Z"

)



with open("guardclaw/ledger/agents/agent-001.json", "w") as f:

&nbsp;   json.dump(agent.to\_dict(), f, indent=2)





Step 6: Initialize Strict Mode

from guardclaw.core.modes import init\_strict\_mode



mode = init\_strict\_mode()

mode.validate\_genesis(genesis)

mode.validate\_agent\_registration(agent)



If validation fails → do not start the system.



Step 7: Start Emitter (Production Defaults)

from guardclaw.core.emitter import init\_global\_emitter



emitter = init\_global\_emitter(

&nbsp;   key\_manager=agent\_key,

&nbsp;   buffer\_dir="guardclaw/buffer",

&nbsp;   signing\_interval\_seconds=1.0,

&nbsp;   batch\_size=100,

&nbsp;   max\_queue\_size=10000

)





Storage \& Retention

Ledger Storage



Format: JSONL (append-only)

One file per event type

Signed records only



ledger/

└── observations/

&nbsp;   ├── intent.jsonl

&nbsp;   ├── execution.jsonl

&nbsp;   ├── result.jsonl

&nbsp;   ├── failure.jsonl



Log Rotation (Required)

For >1M events/day:

\# Daily rotation

mv observations execution\_2026-02-10.jsonl

gzip execution\_2026-02-10.jsonl



Recommended:



Daily rotation

Gzip compression

Immutable storage (WORM / object storage)





Monitoring \& Health Checks

What to Monitor







Signal

Meaning



Heartbeats missing

Observer failure



Queue full

Backpressure



Dropped events

Overload



Signature failures

Crypto/key issue



Health Check Script

stats = emitter.get\_stats()



assert stats\["running"]

assert stats\["queue\_size"] < 9000

assert stats\["total\_dropped"] == 0




Backup Strategy (CRITICAL)

Required Backups





Asset

Frequency

Storage




Genesis key

Once + changes

Offline



Agent keys

On rotation

Secure vault



Ledger

Daily

Off-host





Buffer

Optional

Local only





Genesis Key Backup (Minimum)



3 copies

2 locations

1 offline



If genesis key is lost:



Old evidence remains valid

No new agents can be registered

New genesis required




Hardening Checklist

Production Minimum



\[ ] Strict mode enabled

\[ ] Keys encrypted at rest

\[ ] chmod 600 on all private keys

\[ ] Ledger replicated

\[ ] Time sync (NTP)

\[ ] Log rotation enabled



Regulated / High-Security



\[ ] HSM for signing keys

\[ ] WORM storage for ledger

\[ ] External timestamp authority

\[ ] Key ceremony documented

\[ ] Incident response plan written





Failure Scenarios

If GuardClaw Crashes

✅ Application continues

⚠️ Evidence gap visible (heartbeats)

If Disk Fills

✅ Execution continues

⚠️ Events dropped + logged

If Agent Key Compromised

❌ Trust in that agent lost

✅ Other agents unaffected



What NOT To Do

❌ Do not block execution on GuardClaw

❌ Do not delete ledger files silently

❌ Do not reuse agent keys across systems

❌ Do not store genesis key on app servers



Summary

GuardClaw deployment is:



Simple (single process, local files)

Robust (crash-safe, fail-loud)

Auditable (signed, replayable)

Composable (works with existing systems)




Deploy GuardClaw like logging infrastructure —

but treat its keys like cryptographic assets.




Document Status: FINAL

Applies To: GuardClaw v0.1.x+


