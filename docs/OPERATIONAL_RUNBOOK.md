\# GuardClaw Operational Runbook



\*\*Document Version:\*\* 1.0  

\*\*Protocol Version:\*\* 3.0 (Phase 5)  

\*\*Status:\*\* OPERATIONAL / DAY-2  

\*\*Last Updated:\*\* February 10, 2026



---



\## Purpose



This runbook defines \*\*day-2 operations\*\* for GuardClaw in production:



\- Monitoring \& alerts

\- Incident response

\- On-call procedures

\- Failure handling

\- Audit \& legal workflows

\- Maintenance \& rotation



This document assumes:

\- GuardClaw is already deployed (see DEPLOYMENT\_GUIDE.md)

\- Strict mode is enabled

\- Operators are not developers



---



\## GuardClaw Operating Model (Mental Model)



GuardClaw is \*\*not\*\*:

\- A policy engine

\- An enforcement layer

\- A prevention system



GuardClaw \*\*is\*\*:

\- A cryptographic witness

\- A tamper-evident recorder

\- An accountability substrate



\*\*Operational consequence:\*\*

> If GuardClaw is unhealthy, execution MUST continue —  

> but operators MUST know immediately.



---



\## 1️⃣ Normal Operating State



\### Healthy System Signals



All of the following must be true:



\- ✅ Heartbeats present and regular

\- ✅ Queue size stable (not growing)

\- ✅ `total\_dropped == 0` (or extremely low)

\- ✅ Signatures verify successfully

\- ✅ Ledger files growing monotonically

\- ✅ System clock stable (NTP synced)



---



\### Daily Health Check (Required)



Run once per day (automated or manual):



```python

stats = emitter.get\_stats()



assert stats\["running"] is True

assert stats\["queue\_size"] < 0.9 \* MAX\_QUEUE\_SIZE

assert stats\["total\_dropped"] == 0

assert stats\["total\_signed"] >= stats\["total\_emitted"] \* 0.99



If any assertion fails → investigate immediately.



2️⃣ Monitoring \& Alerts

Metrics to Collect







Metric

Threshold

Severity









Missing heartbeats

>2 intervals

HIGH





Queue utilization

>80%

MEDIUM





Dropped events

>0 sustained

HIGH





Signature failures

>0

CRITICAL





Disk usage

>85%

HIGH





Time drift

>30s

MEDIUM









Alerting Rules (Recommended)

🚨 Critical Alerts (Page Immediately)



Signature verification failure

Genesis validation failure

Agent registration invalid

Ledger corruption detected



⚠️ High Alerts (Investigate Same Day)



Dropped events detected

Heartbeat gaps

Disk nearing capacity

Queue saturation



ℹ️ Informational



Agent stopped (expected tombstone)

Key rotation events

Log rotation completed





3️⃣ Incident Response Playbooks



Incident A: Missing Heartbeats

Symptoms:



No heartbeat events for observer

Replay shows gap

Tombstone may or may not exist



Impact:



Evidence gap (visible)

Execution continued



Response:



Restart observer/emitter process

Confirm new heartbeat emitted

Document gap start/end times

Review actions during gap

Attach gap explanation to audit log



Severity: HIGH

Escalation: If repeated → investigate stability



Incident B: Dropped Events

Symptoms:



total\_dropped > 0

Queue consistently full



Impact:



Partial loss of evidence

Detectable, but not recoverable



Response:



Increase max\_queue\_size

Reduce event volume (sampling, batching)

Increase signer throughput (batch size)

Review hardware limits

Document drop window



Severity: HIGH

Escalation: If sustained → capacity planning required



Incident C: Signature Verification Failure

Symptoms:



Replay marks signature\_valid = false

Verification errors in logs



Impact:



Evidence integrity compromised



Response (IMMEDIATE):



Stop consuming evidence

Isolate ledger (read-only)

Identify affected time window

Verify keys (agent + genesis)

Restore from backup if possible

Generate incident report



Severity: CRITICAL

Escalation: Security + Legal immediately



Incident D: Agent Key Compromise

Symptoms:



Unexpected valid signatures

Actions outside normal behavior

Insider report



Impact:



Trust in that agent’s evidence lost



Response:



Revoke agent immediately

Generate new agent key

Register new agent

Audit all evidence from compromised key

Flag affected records



Severity: CRITICAL

Escalation: Security + Compliance



Incident E: Genesis Key Lost

Symptoms:



Cannot register new agents

Root key unavailable



Impact:



Ledger becomes immutable

Existing evidence remains valid



Response:



Attempt recovery from backups

Attempt Shamir reconstruction (if used)

If unrecoverable:



Declare genesis permanently closed

Create new genesis (new ledger)





Document loss event permanently



Severity: CRITICAL

Escalation: Executive decision required



4️⃣ On-Call Procedures

On-Call Responsibilities

On-call engineer must be able to:



Read replay output

Interpret heartbeats \& tombstones

Validate signatures

Escalate appropriately



They do not need:



Cryptography expertise

Legal judgment

Application domain knowledge





On-Call Decision Tree

Alert triggered

&nbsp;  |

&nbsp;  ├─ Is execution broken?

&nbsp;  |     └─ NO → Continue

&nbsp;  |

&nbsp;  ├─ Is evidence integrity broken?

&nbsp;  |     └─ YES → STOP, escalate

&nbsp;  |

&nbsp;  ├─ Is evidence missing?

&nbsp;  |     └─ YES → document gap

&nbsp;  |

&nbsp;  └─ Is system overloaded?

&nbsp;        └─ YES → scale or throttle





5️⃣ Audit \& Legal Requests

Preparing Evidence for Audit

Steps:



Freeze ledger directory (read-only)

Copy evidence to secure bundle

Include:



genesis.json

agent registrations

observations/





Verify signatures offline

Generate replay summary





Evidence Bundle Structure

evidence\_bundle/

├── genesis.json

├── agents/

│   └── agent-001.json

└── observations/

&nbsp;   ├── execution.jsonl

&nbsp;   ├── result.jsonl

&nbsp;   └── tombstone.jsonl





What Auditors Care About

Auditors / courts will ask:



Can evidence be modified? → No (signatures)

Are gaps detectable? → Yes (heartbeats)

Who signed this? → Key-bound identity

Can you replay events? → Yes (Replay CLI)



They do not care:



Which framework you used

How your agents work internally

Your policy logic





6️⃣ Maintenance Procedures

Key Rotation (Planned)

Frequency: 12 months

Steps:



Generate new agent key

Register new agent

Switch emitter to new key

Revoke old agent

Retain old key for verification



No downtime required.



Log Rotation

Minimum:



Daily rotation for >1M events/day

Weekly for smaller volumes



Always:



Compress archives

Store off-host

Verify checksums





Software Upgrades

Rules:



Never modify existing evidence files

New protocol version → new files, not rewrites

Old evidence must remain verifiable forever



Upgrade steps:



Stop emitter

Backup ledger + buffer

Upgrade GuardClaw

Restart emitter

Verify replay consistency





7️⃣ What To Do During an Outage

If the application is down:



GuardClaw likely down too

Evidence gap expected

Document outage window



If GuardClaw is down but app is running:



This is worse

Evidence gap without execution failure

Escalate immediately





8️⃣ Common Operator Mistakes (Avoid These)

❌ Deleting ledger files to “clean up”

❌ Silencing dropped-event alerts

❌ Sharing agent keys between systems

❌ Storing genesis key on CI/CD runners

❌ Treating GuardClaw as enforcement



9️⃣ Final Operator Checklist

Before declaring GuardClaw “healthy”:



\[ ] Heartbeats present

\[ ] Queue stable

\[ ] No dropped events

\[ ] Signatures verify

\[ ] Ledger backed up

\[ ] Keys secured

\[ ] Replay tested





Final Statement

GuardClaw operations succeed when:



Failures are visible

Gaps are documented

Evidence is never silently altered

Operators trust the system’s honesty





A system that admits what it cannot see

is stronger than one that pretends to see everything.





Document Status: FINAL

Applies To: Phase 5+

Runbook Owner: Security / Platform Team

Review Cycle: Quarterly



