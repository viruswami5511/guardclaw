
"""
tests/test_registry.py -- KeyRegistry full adversarial test suite
"""
import pytest
import json
from pathlib import Path
from guardclaw.core.registry import (
    KeyRegistry, KeyRecord,
    KeyNotFoundError, KeyRevokedError, KeyConflictError, KeyMismatchError,
)

FAKE_KEY_A = "a" * 64
FAKE_KEY_B = "b" * 64
FAKE_KEY_C = "c" * 64


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_and_resolve():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A, agent_id="agent-1")
    rec = r.resolve("k1")
    assert rec.public_key_hex == FAKE_KEY_A
    assert rec.agent_id == "agent-1"
    assert not rec.revoked

def test_register_duplicate_raises():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    with pytest.raises(KeyConflictError):
        r.register("k1", FAKE_KEY_B)

def test_register_allow_update():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.register("k1", FAKE_KEY_B, allow_update=True)
    assert r.resolve("k1").public_key_hex == FAKE_KEY_B

def test_register_invalid_key_id():
    r = KeyRegistry()
    with pytest.raises(ValueError):
        r.register("", FAKE_KEY_A)
    with pytest.raises(ValueError):
        r.register("   ", FAKE_KEY_A)

def test_register_invalid_pubkey():
    r = KeyRegistry()
    with pytest.raises(ValueError):
        r.register("k1", "tooshort")
    with pytest.raises(ValueError):
        r.register("k1", "x" * 63)

# ── Resolution ────────────────────────────────────────────────────────────────

def test_resolve_not_found():
    r = KeyRegistry()
    with pytest.raises(KeyNotFoundError):
        r.resolve("ghost-key")

def test_resolve_public_key():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    assert r.resolve_public_key("k1") == FAKE_KEY_A

# ── Binding verification ──────────────────────────────────────────────────────

def test_verify_binding_ok():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.verify_binding("k1", FAKE_KEY_A)  # should not raise

def test_verify_binding_mismatch():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    with pytest.raises(KeyMismatchError):
        r.verify_binding("k1", FAKE_KEY_B)

def test_verify_binding_not_found():
    r = KeyRegistry()
    with pytest.raises(KeyNotFoundError):
        r.verify_binding("ghost", FAKE_KEY_A)

def test_verify_binding_revoked():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.revoke("k1")
    with pytest.raises(KeyRevokedError):
        r.verify_binding("k1", FAKE_KEY_A)

# ── Revocation ────────────────────────────────────────────────────────────────

def test_revoke_sets_fields():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.revoke("k1", reason="compromised")
    rec = r._records["k1"]
    assert rec.revoked
    assert rec.revocation_reason == "compromised"
    assert rec.revoked_at is not None

def test_revoke_idempotent():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.revoke("k1")
    r.revoke("k1")  # should not raise
    assert r.is_revoked("k1")

def test_revoke_not_found():
    r = KeyRegistry()
    with pytest.raises(KeyNotFoundError):
        r.revoke("ghost")

def test_is_revoked_false_for_active():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    assert not r.is_revoked("k1")

def test_is_revoked_false_for_unknown():
    r = KeyRegistry()
    assert not r.is_revoked("unknown")

def test_resolve_revoked_raises():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.revoke("k1")
    with pytest.raises(KeyRevokedError):
        r.resolve("k1")

# ── Introspection ─────────────────────────────────────────────────────────────

def test_list_keys_excludes_revoked_by_default():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.register("k2", FAKE_KEY_B)
    r.revoke("k2")
    keys = r.list_keys()
    assert len(keys) == 1
    assert keys[0].key_id == "k1"

def test_list_keys_include_revoked():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.register("k2", FAKE_KEY_B)
    r.revoke("k2")
    keys = r.list_keys(include_revoked=True)
    assert len(keys) == 2

def test_has_key():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    assert r.has_key("k1")
    assert not r.has_key("k2")

def test_len():
    r = KeyRegistry()
    assert len(r) == 0
    r.register("k1", FAKE_KEY_A)
    r.register("k2", FAKE_KEY_B)
    assert len(r) == 2

# ── Persistence ───────────────────────────────────────────────────────────────

def test_save_and_load(tmp_path):
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A, agent_id="a1")
    r.register("k2", FAKE_KEY_B, agent_id="a2")
    r.revoke("k2", reason="expired")

    path = tmp_path / "registry.json"
    r.save(path)

    r2 = KeyRegistry.load(path)
    assert len(r2) == 2
    assert r2.has_key("k1")
    assert r2.is_revoked("k2")
    rec = r2._records["k2"]
    assert rec.revocation_reason == "expired"

def test_load_not_found():
    with pytest.raises(FileNotFoundError):
        KeyRegistry.load(Path("/nonexistent/registry.json"))

def test_save_creates_parent_dirs(tmp_path):
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    path = tmp_path / "deep" / "nested" / "registry.json"
    r.save(path)
    assert path.exists()

# ── Repr ──────────────────────────────────────────────────────────────────────

def test_repr():
    r = KeyRegistry()
    r.register("k1", FAKE_KEY_A)
    r.revoke("k1")
    assert "total=1" in repr(r)
    assert "revoked=1" in repr(r)