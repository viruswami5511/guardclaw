\# Ghost Mode vs Strict Mode



GuardClaw supports two operational modes with different security guarantees.



---



\## Quick Comparison



| Feature | Ghost Mode | Strict Mode |

|---------|------------|-------------|

| \*\*Use Case\*\* | Development, testing | Production, compliance |

| \*\*Setup\*\* | Zero ceremony | Explicit genesis + registration |

| \*\*Keys\*\* | Ephemeral (saved for replay) | Persistent (HSM-ready) |

| \*\*Genesis\*\* | Auto-generated | Explicit, signed by root key |

| \*\*Agent Registration\*\* | Auto-generated | Explicit, signed by root key |

| \*\*Authority Enforcement\*\* | Warnings only | Hard failures |

| \*\*Delegation Checks\*\* | Skipped | Enforced |

| \*\*Expiry Checks\*\* | Skipped | Enforced |

| \*\*Tampering Detection\*\* | ✅ Same | ✅ Same |

| \*\*Signature Verification\*\* | ✅ Same | ✅ Same |



---



\## Ghost Mode



\*\*Purpose:\*\* Fast development iteration with zero setup friction.



\### Characteristics



✅ \*\*Zero Ceremony:\*\*

```python

from guardclaw import init\_ghost\_mode, init\_global\_emitter



mode = init\_ghost\_mode()

emitter = init\_global\_emitter(key\_manager=mode.get\_ephemeral\_agent\_key())

\# Ready to go



✅ Ephemeral Keys (Saved for Replay):



Keys generated on startup



Saved to .guardclaw/keys/ for replay verification



Not suitable for long-term production



✅ Auto-Generated Genesis:



Genesis created automatically



No explicit ceremony required



Warning banner shown



⚠️ Warnings Only:



Missing genesis → Warning (not failure)



Expired keys → Warning (not failure)



Invalid delegation → Warning (not failure)



Security Guarantees

Property	Ghost Mode

Tamper-evident	✅ Yes (cryptographic)

Detects modifications	✅ Yes

Detects deletions	✅ Yes (heartbeats)

Authority enforcement	⚠️ No

Prevents forgery	⚠️ No (ephemeral keys)

Compliance-ready	❌ No

When to Use

✅ Local development



✅ Unit/integration testing



✅ Debugging agent behavior



✅ Prototyping new agents



❌ Production deployments



❌ Compliance/audit requirements



❌ Multi-agent systems with trust boundaries



Strict Mode

Purpose: Production-grade accountability with explicit authority chains.



Characteristics

✅ Explicit Genesis:



python

from guardclaw import init\_strict\_mode

from guardclaw.core.crypto import Ed25519KeyManager

from guardclaw.core.genesis import GenesisRecord



\# Must create genesis explicitly

root\_key = Ed25519KeyManager.generate()

genesis = GenesisRecord.create(

&nbsp;   ledger\_name="Production Ledger",

&nbsp;   created\_by="admin@company.com",

&nbsp;   root\_key\_manager=root\_key,

&nbsp;   purpose="Production accountability"

)

✅ Explicit Agent Registration:



python

from guardclaw.core.genesis import AgentRegistration



agent\_key = Ed25519KeyManager.generate()

agent\_reg = AgentRegistration.create(

&nbsp;   agent\_id="prod-agent-001",

&nbsp;   agent\_name="Production Agent",

&nbsp;   registered\_by="admin@company.com",

&nbsp;   delegating\_key\_manager=root\_key,

&nbsp;   agent\_key\_manager=agent\_key,

&nbsp;   capabilities=\["data:read", "data:write"],

&nbsp;   valid\_from="2026-01-01T00:00:00Z",

&nbsp;   valid\_until="2026-12-31T23:59:59Z"

)

✅ Authority Enforcement:



Missing genesis → Hard failure



Missing agent registration → Hard failure



Invalid delegation → Hard failure



Expired keys → Hard failure



✅ Persistent Keys:



Keys stored in secure key management



HSM-compatible



Rotation supported



Security Guarantees

Property	Strict Mode

Tamper-evident	✅ Yes (cryptographic)

Detects modifications	✅ Yes

Detects deletions	✅ Yes (heartbeats)

Authority enforcement	✅ Yes

Prevents forgery	✅ Yes (genesis chain)

Compliance-ready	✅ Yes

When to Use

✅ Production deployments



✅ Compliance/audit requirements (SOC2, GDPR, etc.)



✅ Multi-agent systems



✅ Trust boundaries between agents



✅ Legal evidence collection



✅ Financial/healthcare applications



Cryptographic Security (Same in Both Modes)

Both modes use identical cryptography:



Signing: Ed25519



Hashing: SHA-256



Canonicalization: Deterministic JSON



Tampering Detection

Both modes detect tampering identically:



Event signed: signature = Ed25519.sign(event, private\_key)



Event stored: {event, signature}



Replay verifies: Ed25519.verify(signature, event, public\_key)



Modified event → Signature verification fails



Example:



bash

\# Original event

{"action": "file:delete", "timestamp": "2026-02-11T00:00:00Z"}



\# Attacker modifies

{"action": "file:read", "timestamp": "2026-02-11T00:00:00Z"}



\# Replay detects

🚨 INVALID (TAMPERED)

🚨 WARNING: Event has been modified after signing!

Authority Enforcement (Strict Mode Only)

Strict mode adds authority verification:



text

Event signed by Agent A

&nbsp; ↓

Replay checks:

&nbsp; 1. Does genesis exist?

&nbsp; 2. Is genesis signature valid?

&nbsp; 3. Is Agent A registered?

&nbsp; 4. Is Agent A's registration signed by root key?

&nbsp; 5. Is Agent A within valid time range?

&nbsp; 6. Does Agent A have required capability?

&nbsp; ↓

If any check fails → UNAUTHORIZED

Ghost mode skips these checks (warnings only).



Key Rotation

Ghost Mode

Not supported (ephemeral keys)



Restart generates new keys



Strict Mode

Full key rotation supported



Old events remain valid (historical verification)



New events signed with new key



Timeline shows key transition



Example:



bash

\# Register agent with Key v1

AgentRegistration.create(..., agent\_key\_manager=key\_v1)



\# Events signed with Key v1

...



\# Rotate to Key v2

AgentRegistration.create(..., agent\_key\_manager=key\_v2)



\# Events signed with Key v2

...



\# Replay verifies both

✅ Events 1-100: Key v1 (valid)

✅ Events 101-200: Key v2 (valid)

Migration Path

Development → Production:



bash

\# 1. Develop with Ghost mode

python my\_agent.py  # Uses Ghost mode by default



\# 2. Test in Strict mode (pre-production)

export GUARDCLAW\_MODE=strict

python setup\_production.py  # Create genesis + agent



\# 3. Deploy to production

python my\_agent.py  # Now uses Strict mode

Environment Variables

bash

\# Set mode explicitly

export GUARDCLAW\_MODE=ghost    # Development

export GUARDCLAW\_MODE=strict   # Production

Default: Ghost mode (if not set)



Summary

Ghost Mode

Fast: Zero setup



Flexible: No ceremony



Dev-friendly: Warnings only



Not production-ready



Strict Mode

Secure: Authority enforced



Auditable: Compliance-ready



Production-grade: Hard failures



Requires setup



Choose based on context:



Dev/test → Ghost



Prod/compliance → Strict





