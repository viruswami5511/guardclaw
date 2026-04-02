"""
guardclaw/pytest_plugin.py

GuardClaw pytest plugin — automatic cryptographic evidence per test.

Auto-loaded via pyproject.toml:
    [project.entry-points."pytest11"]
    guardclaw = "guardclaw.pytest_plugin"

Install with: pip install -e .

Opt-out:
    Per-test:   @pytest.mark.no_guardclaw
    CLI:        pytest --no-guardclaw
    Env:        GUARDCLAW_DISABLE=1
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from guardclaw.api import GEFSession
from guardclaw.core.emitter import get_global_ledger, set_global_ledger


# ── Path display helper ───────────────────────────────────────

def _display_path(p: str) -> str:
    try:
        return str(Path(p).relative_to(Path.cwd()))
    except Exception:
        return p


# ─────────────────────────────────────────────────────────────
# CLI options + marker registration
# ─────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    group = parser.getgroup("guardclaw")
    group.addoption(
        "--no-guardclaw",
        action="store_true",
        default=False,
        help="Disable GuardClaw session recording for this run.",
    )
    group.addoption(
        "--guardclaw-dir",
        action="store",
        default="guardclaw-artifacts",
        help="Directory to store .gef ledger artifacts (default: guardclaw-artifacts).",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_guardclaw: disable GuardClaw recording for this test",
    )


# ─────────────────────────────────────────────────────────────
# Per-test fixture
# ─────────────────────────────────────────────────────────────

_artifact_count = 0


@pytest.fixture(autouse=True)
def guardclaw_session(request):
    """
    Auto-injected per-test fixture.

    Opens a GEFSession per test and swaps the global ledger so that
    any guardclaw.record_action() calls inside the test body also
    route to the same session ledger — one chain, complete evidence.

    Saves a signed .gef JSONL artifact after each test that recorded entries.
    Prints the artifact path AFTER file write (not before, not inside try block).
    """
    global _artifact_count

    # Opt-out: env var
    if os.environ.get("GUARDCLAW_DISABLE", "").strip() == "1":
        yield None
        return

    # Opt-out: CLI flag
    if request.config.getoption("--no-guardclaw", default=False):
        yield None
        return

    # Opt-out: per-test marker
    if request.node.get_closest_marker("no_guardclaw"):
        yield None
        return

    agent_id = request.node.nodeid.replace("::", ".")[:128]
    session = GEFSession(agent_id=agent_id)

    # Swap global ledger so record_action() calls route here too
    old_ledger = get_global_ledger()
    set_global_ledger(session._ledger)

    try:
        yield session
    finally:
        # Always restore original ledger first
        set_global_ledger(old_ledger)

        entries = session.entries()
        if not entries:
            return

        artifact_dir = Path(request.config.getoption("--guardclaw-dir"))
        artifact_dir.mkdir(parents=True, exist_ok=True)

        filename = (
            request.node.nodeid
            .replace("::", "__")
            .replace("/", "_")
            .replace(" ", "_")
            + f"__{session.session_id[:8]}.gef"
        )
        path = artifact_dir / filename

        try:
            with open(path, "w", encoding="utf-8") as f:
                for env in entries:
                    f.write(json.dumps(env.to_dict()) + "\n")
            _artifact_count += 1

            # Print AFTER file is written — not before, not inside try
            dp = _display_path(str(path))
            print(f"\n[guardclaw] Ledger written: {dp}")
            print(f"  Verify:   guardclaw verify {dp}")
            print(f"  Export:   guardclaw export {dp}")

        except Exception as e:
            print(f"\n[guardclaw] WARNING: Failed to write artifact {path}: {e}")


# ─────────────────────────────────────────────────────────────
# Capture test pass/fail for metadata (optional hook)
# ─────────────────────────────────────────────────────────────

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


# ─────────────────────────────────────────────────────────────
# Session summary
# ─────────────────────────────────────────────────────────────

def pytest_sessionfinish(session, exitstatus):
    if _artifact_count > 0 and os.environ.get("GUARDCLAW_DISABLE", "").strip() != "1":
        artifact_dir = session.config.getoption(
            "--guardclaw-dir", default="guardclaw-artifacts"
        )
        dp = _display_path(str(Path(artifact_dir)))
        print(f"\n[guardclaw] {_artifact_count} signed artifact(s) saved → {dp}/")
        print(f"  Verify all:   guardclaw verify <file>.gef")
        print(f"  Export:       guardclaw export <file>.gef\n")