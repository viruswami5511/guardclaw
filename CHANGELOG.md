# Changelog

All notable changes to GuardClaw are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.2] - 2026-09-04

### Added
- **Ed25519KeyManager.load**: Persistent key loading alias matching `from_file` for agent session workflows.
- **Upstream Agent Adapters**: Direct integration support for Anthropic Model Context Protocol (`modelcontextprotocol/servers`), Nous Research Hermes Agent (`NousResearch/hermes-agent`), and OpenClaw Agent Skills (`openclaw/agent-skills`).
- **Cryptographic Pinned Verification**: CLI and Python verifiers support explicit public-key pinning (`--pinned-key`) to detect directory-substitution attacks.
- **Git Tag & PyPI Alignment**: Synchronized official release tag `v0.8.2` with PyPI package distribution.

### Changed
- Standardized error reporting in `verify_ledger` when operating on unsigned or uninitialized vaults (`chain_valid: None`).
- Hardened multi-mutation persistence across agent sessions.

## [0.8.1] - 2026-08-30

### Changed
- Refactored CLI verification command formatting and exit codes.
- Improved RFC 8785 canonicalization compliance checks across boundary payloads.

## [0.7.1] - 2026-04-05

### Changed
- Bumped package version to v0.7.1 for post-0.7.0 docs and packaging fixes.
- Aligned SPEC.md, GEF-SPEC docs, and SECURITY.md with the implemented protocol.
- Cleaned escaping in docs and ensured consistent file naming/links.

### Fixed
- Updated build backend (`setuptools.build_meta`) and verified PyPI build.
- Removed stray inline code leakage in README project structure section.

## [0.7.0] - 2026-04-05

### Added
- Deterministic GEF bundle export with full cryptographic verification.
- Ledger crash recovery — partial writes detected and rolled back safely.
- Concurrent verification stress test — 40/40 passed under full load.
- Updated SPEC.md, THREAT_MODEL.md, SECURITY.md for v0.7.0.

### Fixed
- `verify_chain()` attribute mismatch (`chain_valid` vs `chainvalid`).
- Bundle export timestamp nondeterminism (`deterministic=True` mode added).

## [0.6.1] - 2026-03-28

### Fixed
- Signature verification edge cases and non-canonical base64url validation.

## [0.6.0] - 2026-03-20

### Added
- MCP proxy and framework integrations.
- LangChain and CrewAI callback/tool adapters.
