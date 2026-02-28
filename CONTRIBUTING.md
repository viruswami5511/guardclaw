\# Contributing to GuardClaw



Thank you for your interest in GuardClaw.



This is an open-source project implementing

\*\*Replay-Bound Evidence\*\* — a minimal cryptographic framework

for tamper-evident AI agent event records.



---



\## What Kind of Contributions Are Welcome



\### Protocol Critique

\- Identify gaps or weaknesses in the replay invariant

\- Challenge threat model assumptions (Section 6 of the paper)

\- Point out edge cases in canonicalization or nonce enforcement

\- Flag inconsistencies between the protocol spec and the implementation



\### Bug Reports

\- Signature verification failures

\- Nonce/sequence enforcement gaps

\- CLI errors or unexpected behavior

\- Broken documentation links



\### Security Issues

**Do not open a public issue for security vulnerabilities.**
See [SECURITY.md](https://github.com/viruswami5511/guardclaw/blob/master/SECURITY.md) for responsible disclosure instructions.


\### Documentation Improvements

\- Typos, broken links, unclear explanations

\- Corrections to the paper (open an issue, not a PR)



\### Implementation Feedback

\- Performance edge cases

\- Compatibility issues (Python version, platform)

\- Packaging or installation problems



---


## What Is Not in Scope Right Now

\- Blockchain or consensus layer integrations

\- GUI or dashboard tooling

\- New language implementations without first coordinating on test vectors (see SPEC.md Section 12.2)

Level 4 features (RFC 3161 timestamping, key rotation audit trails) are planned but not yet being accepted as PRs. Open an issue to discuss first.


---



\## How to Open an Issue



1\. Check existing issues before opening a new one

2\. Use a clear, descriptive title

3\. For bugs: include Python version, OS, and exact command that failed

4\. For protocol critique: Reference the specific section of [SPEC.md](SPEC.md) or the [paper](docs/replay-bound-evidence-v1.0.md)



---



\## How to Submit a Pull Request



1\. Fork the repository

2\. Create a branch: `git checkout -b fix/your-description`

3\. Make your change

4\. Run the full test suite and ensure all 45 pass: `pytest tests/`

5\. Open a PR with a clear description of what changed and why



Keep PRs small and focused. One fix or improvement per PR.



---



\## Paper Feedback



The paper (`docs/replay-bound-evidence-v1.0.md`) is versioned

separately from the code. To suggest corrections or raise questions

about the framework definition:



\- Open a GitHub Issue tagged `paper`

\- Reference the section number

\- Be specific about what is incorrect or unclear



Version 1.1 will incorporate valid technical critique gathered

from public discussion.



---



\## Code Style



\- Python 3.9+

\- Follow existing patterns in the codebase

\- No new dependencies without discussion

\- Tests required for any functional change



---



\## Questions



Open a [GitHub Issue](https://github.com/viruswami5511/guardclaw/issues).



---



*GuardClaw is maintained by [Viru Swami](https://github.com/viruswami5511).*
