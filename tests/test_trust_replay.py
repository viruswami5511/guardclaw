"""
tests/test_trust_replay.py -- Trust-aware replay engine adversarial tests
All identity tests use real signed records with key_id included at signing time.
"""
import pytest
from pathlib import Path
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.registry import KeyRegistry
from guardclaw.core.replay import ReplayEngine, validate_identity
from guardclaw.core.failure import FailureType, FailureDetail


FAKE_KEY_A = "a" * 64
FAKE_KEY_B = "b" * 64


def _make_ledger(tmp_path, n=3, key_id=None):
    """Create a real signed ledger. key_id is included in signing surface if provided."""
    km = Ed25519KeyManager.generate()
    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(n):
        ledger.emit("execution", {"step": i}, key_id=key_id)
    return km, ledger.get_path()


# ── validate_identity unit tests ──────────────────────────────────────────────

class MockEnv:
    def __init__(self, key_id, pubkey):
        self.key_id = key_id
        self.signer_public_key = pubkey


def test_validate_identity_no_key_id_skips():
    registry = KeyRegistry()
    assert validate_identity(MockEnv(None, FAKE_KEY_A), registry) is None


def test_validate_identity_key_found_matches():
    registry = KeyRegistry()
    registry.register("k1", FAKE_KEY_A)
    assert validate_identity(MockEnv("k1", FAKE_KEY_A), registry) is None


def test_validate_identity_unknown_key_id():
    registry = KeyRegistry()
    result = validate_identity(MockEnv("ghost", FAKE_KEY_A), registry)
    assert result == (FailureType.IDENTITY_VIOLATION, FailureDetail.UNKNOWN_KEY_ID)


def test_validate_identity_revoked_key():
    registry = KeyRegistry()
    registry.register("k1", FAKE_KEY_A)
    registry.revoke("k1")
    result = validate_identity(MockEnv("k1", FAKE_KEY_A), registry)
    assert result == (FailureType.IDENTITY_VIOLATION, FailureDetail.REVOKED_KEY)


def test_validate_identity_key_mismatch():
    registry = KeyRegistry()
    registry.register("k1", FAKE_KEY_A)
    result = validate_identity(MockEnv("k1", FAKE_KEY_B), registry)
    assert result == (FailureType.IDENTITY_VIOLATION, FailureDetail.KEY_ID_MISMATCH)


# ── Backward compatibility ────────────────────────────────────────────────────

def test_replay_no_registry_passes_v1_ledger(tmp_path):
    """v1.0 ledgers with no key_id pass without registry."""
    _, path = _make_ledger(tmp_path, key_id=None)
    summary = ReplayEngine(mode="strict").stream_verify(Path(path))
    assert summary.chain_valid
    assert summary.identity_enforced is False


def test_replay_with_registry_no_key_id_identity_not_enforced(tmp_path):
    """Registry present but records have no key_id → identity_enforced=False."""
    _, path = _make_ledger(tmp_path, key_id=None)
    registry = KeyRegistry()
    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(Path(path))
    assert summary.chain_valid
    assert summary.identity_enforced is False  # no record had key_id


# ── Real identity enforcement (valid signed records with key_id) ──────────────

def test_replay_registered_key_passes(tmp_path):
    """Ledger with key_id that is registered and active must pass."""
    km = Ed25519KeyManager.generate()
    key_id = "agent-key-001"
    registry = KeyRegistry()
    registry.register(key_id, km.public_key_hex, agent_id="test-agent")

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(3):
        ledger.emit("execution", {"step": i}, key_id=key_id)

    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(
        Path(ledger.get_path())
    )
    assert summary.chain_valid
    assert summary.identity_enforced is True


def test_replay_revoked_key_fails(tmp_path):
    """Ledger with revoked key_id must fail with REVOKED_KEY."""
    km = Ed25519KeyManager.generate()
    key_id = "agent-key-002"
    registry = KeyRegistry()
    registry.register(key_id, km.public_key_hex)

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(3):
        ledger.emit("execution", {"step": i}, key_id=key_id)

    registry.revoke(key_id, reason="compromised")

    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(
        Path(ledger.get_path())
    )
    assert not summary.chain_valid
    assert summary.failure_type == FailureType.IDENTITY_VIOLATION
    assert summary.failure_detail == FailureDetail.REVOKED_KEY
    assert summary.identity_enforced is True


def test_replay_unknown_key_id_fails(tmp_path):
    """Ledger with key_id not in registry must fail with UNKNOWN_KEY_ID."""
    km = Ed25519KeyManager.generate()
    key_id = "unregistered-key-xyz"
    registry = KeyRegistry()
    # Deliberately do NOT register the key

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(3):
        ledger.emit("execution", {"step": i}, key_id=key_id)

    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(
        Path(ledger.get_path())
    )
    assert not summary.chain_valid
    assert summary.failure_type == FailureType.IDENTITY_VIOLATION
    assert summary.failure_detail == FailureDetail.UNKNOWN_KEY_ID
    assert summary.identity_enforced is True


def test_replay_recovery_mode_revoked_key_reports_boundary(tmp_path):
    """Recovery mode: identity failure reports correct boundary and verified_count."""
    km = Ed25519KeyManager.generate()
    key_id = "agent-key-003"
    registry = KeyRegistry()
    registry.register(key_id, km.public_key_hex)

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    # Emit genesis (no key_id) + 3 records with key_id
    for i in range(3):
        ledger.emit("execution", {"step": i}, key_id=key_id)

    registry.revoke(key_id)

    summary = ReplayEngine(mode="recovery", registry=registry).stream_verify(
        Path(ledger.get_path())
    )
    assert not summary.chain_valid
    assert summary.recovery_mode_active
    assert summary.failure_type == FailureType.IDENTITY_VIOLATION
    assert summary.failure_detail == FailureDetail.REVOKED_KEY
    # boundary should be the last valid record BEFORE the first key_id record
    # (genesis has no key_id so it passes; first execution record fails)
    assert summary.verified_count >= 1


def test_replay_mixed_key_id_and_no_key_id(tmp_path):
    """Mixed ledger: some records with key_id, some without. All should pass if key registered."""
    km = Ed25519KeyManager.generate()
    key_id = "agent-key-004"
    registry = KeyRegistry()
    registry.register(key_id, km.public_key_hex)

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    ledger.emit("execution", {"step": 0})              # no key_id
    ledger.emit("execution", {"step": 1}, key_id=key_id)  # with key_id
    ledger.emit("execution", {"step": 2})              # no key_id
    ledger.emit("execution", {"step": 3}, key_id=key_id)  # with key_id

    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(
        Path(ledger.get_path())
    )
    assert summary.chain_valid
    assert summary.identity_enforced is True  # at least one key_id record was checked


def test_replay_identity_enforced_false_when_no_key_id_records(tmp_path):
    """Registry provided but zero records have key_id → identity_enforced=False."""
    _, path = _make_ledger(tmp_path, n=5, key_id=None)
    registry = KeyRegistry()
    summary = ReplayEngine(mode="strict", registry=registry).stream_verify(Path(path))
    assert summary.chain_valid
    assert summary.identity_enforced is False


# ── Summary field correctness ─────────────────────────────────────────────────

def test_summary_to_dict_includes_identity_enforced(tmp_path):
    _, path = _make_ledger(tmp_path)
    summary = ReplayEngine(mode="strict").stream_verify(Path(path))
    d = summary.to_dict()
    assert "identity_enforced" in d
    assert d["identity_enforced"] is False