\# Changelog



All notable changes to GuardClaw are documented here.

Format follows \[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).



\## \[0.7.1] - 2026-04-05

\### Changed

\- Bumped package version to v0.7.1 for post-0.7.0 docs and packaging fixes

\- Aligned SPEC.md, GEF-SPEC docs, and SECURITY.md with the implemented protocol

\- Cleaned mojibake/escaping in docs and ensured consistent file naming/links



\### Fixed

\- Updated build backend (setuptools.build\_meta) and verified 0.7.1 PyPI build

\- Removed stray inline code leakage in README project structure section



\## \[0.7.0] - 2026-04-05

\### Added

\- Deterministic GEF bundle export with full cryptographic verification

\- Ledger crash recovery — partial writes detected and rolled back safely

\- Concurrent verification stress test — 40/40 passed under full load

\- Updated SPEC.md, THREAT\_MODEL.md, SECURITY.md for v0.7.0



\### Fixed

\- verify\_chain() attribute mismatch (chain\_valid vs chainvalid)

\- Bundle export timestamp nondeterminism (deterministic=True mode added)



\## \[0.6.1] - 2026-03-28

\### Fixed

\- Signature verification edge cases



\## \[0.6.0] - 2026-03-20

\### Added

\- MCP proxy and framework integrations

\- LangChain and CrewAI adapters



\## \[0.5.2] - 2026-03-10

\### Added

\- GEF-SPEC-1.0 stabilization

\- CLI module support

