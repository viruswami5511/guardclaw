"""
tests/test_encryption.py -- Phase 3 AES-256-GCM encryption adversarial tests

All tests use real signed envelopes. Encryption happens before signing.
"""
import json
import pytest
from pathlib import Path
from cryptography.exceptions import InvalidTag

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.encryption import EncryptionManager, b64url_encode, b64url_decode
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import ExecutionEnvelope
from guardclaw.core.replay import ReplayEngine


SAMPLE_PAYLOAD = {"action": "tool_call", "tool": "search", "query": "test input"}


# ── EncryptionManager unit tests ──────────────────────────────────────────────

def test_generate_produces_32_byte_key():
    em = EncryptionManager.generate()
    assert len(bytes.fromhex(em.export_master_key_hex())) == 32


def test_from_hex_roundtrip():
    em = EncryptionManager.generate()
    em2 = EncryptionManager.from_hex(em.export_master_key_hex())
    assert em.export_master_key_hex() == em2.export_master_key_hex()


def test_from_hex_invalid_raises():
    with pytest.raises(ValueError):
        EncryptionManager.from_hex("not-hex-data")


def test_wrong_key_length_raises():
    with pytest.raises(ValueError):
        EncryptionManager(b"short")


# ── Round-trip tests ──────────────────────────────────────────────────────────

def _make_env(key_id=None):
    km = Ed25519KeyManager.generate()
    env = ExecutionEnvelope.create(
        record_type="EXECUTION",
        agent_id="test-agent",
        session_id="sess-001",
        signer_public_key=km.public_key_hex,
        sequence=1,
        payload=SAMPLE_PAYLOAD,
        prev=None,
        key_id=key_id,
    )
    return km, env


def test_encrypt_decrypt_roundtrip():
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    result = em.decrypt(env)
    assert result == SAMPLE_PAYLOAD


def test_encrypt_sets_cipher_suite_1():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    assert env.cipher_suite == 1


def test_encrypt_sets_iv_and_auth_tag():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    assert env.iv is not None
    assert env.auth_tag is not None
    assert len(env.iv) > 0
    assert len(env.auth_tag) > 0


def test_encrypt_payload_becomes_string():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    assert isinstance(env.payload, str)


def test_iv_is_base64url_no_padding():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    assert '=' not in env.iv
    assert '=' not in env.auth_tag


def test_different_records_get_different_ivs():
    """Random IV — no two records should have same IV."""
    km = Ed25519KeyManager.generate()
    em = EncryptionManager.generate()
    ivs = set()
    for i in range(10):
        env = ExecutionEnvelope.create(
            record_type="EXECUTION",
            agent_id="agent",
            session_id="sess",
            signer_public_key=km.public_key_hex,
            sequence=i,
            payload={"i": i},
            prev=None,
        )
        em.encrypt(env)
        ivs.add(env.iv)
    assert len(ivs) == 10  # all unique


# ── Tamper detection ──────────────────────────────────────────────────────────

def test_tamper_ciphertext_fails_decrypt():
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    # Corrupt ciphertext
    ct_bytes = b64url_decode(env.payload, "payload")
    corrupted = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
    env.payload = b64url_encode(corrupted)
    with pytest.raises(InvalidTag):
        em.decrypt(env)


def test_tamper_auth_tag_fails_decrypt():
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    tag_bytes = b64url_decode(env.auth_tag, "auth_tag")
    corrupted_tag = bytes([tag_bytes[0] ^ 0xFF]) + tag_bytes[1:]
    env.auth_tag = b64url_encode(corrupted_tag)
    with pytest.raises(InvalidTag):
        em.decrypt(env)


# ── AAD binding tests ─────────────────────────────────────────────────────────

def test_aad_binding_sequence_change_fails():
    """Changing sequence after encryption breaks AAD → decrypt fails."""
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    env.sequence = 999  # tamper AAD field
    with pytest.raises(InvalidTag):
        em.decrypt(env)


def test_aad_binding_session_change_fails():
    """Changing session_id after encryption breaks AAD → decrypt fails."""
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    env.session_id = "tampered-session"
    with pytest.raises(InvalidTag):
        em.decrypt(env)


def test_aad_binding_agent_change_fails():
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    env.agent_id = "tampered-agent"
    with pytest.raises(InvalidTag):
        em.decrypt(env)


# ── Cross-record replay attack ────────────────────────────────────────────────

def test_cross_record_replay_blocked():
    """Copy ciphertext from record A into record B — decrypt must fail."""
    km = Ed25519KeyManager.generate()
    em = EncryptionManager.generate()

    env_a = ExecutionEnvelope.create(
        record_type="EXECUTION", agent_id="agent",
        session_id="sess", signer_public_key=km.public_key_hex,
        sequence=0, payload={"src": "A"}, prev=None,
    )
    env_b = ExecutionEnvelope.create(
        record_type="EXECUTION", agent_id="agent",
        session_id="sess", signer_public_key=km.public_key_hex,
        sequence=1, payload={"src": "B"}, prev=None,
    )

    em.encrypt(env_a)
    em.encrypt(env_b)

    # Transplant ciphertext + iv + auth_tag from A into B
    env_b.payload = env_a.payload
    env_b.iv = env_a.iv
    env_b.auth_tag = env_a.auth_tag

    with pytest.raises(InvalidTag):
        em.decrypt(env_b)


# ── Wrong key fails ───────────────────────────────────────────────────────────

def test_wrong_master_key_fails():
    km, env = _make_env()
    em1 = EncryptionManager.generate()
    em2 = EncryptionManager.generate()
    em1.encrypt(env)
    env.sign(km)
    with pytest.raises(InvalidTag):
        em2.decrypt(env)


def test_wrong_key_id_in_derivation_fails():
    """key_id is part of HKDF info — changing it changes the derived key."""
    km, env = _make_env(key_id="original-key")
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    env.key_id = "different-key"  # change key_id after encryption
    with pytest.raises(InvalidTag):
        em.decrypt(env)


# ── Tag truncation ────────────────────────────────────────────────────────────

def test_truncated_auth_tag_fails():
    km, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.sign(km)
    # Truncate auth_tag to 8 bytes
    tag_bytes = b64url_decode(env.auth_tag, "auth_tag")
    env.auth_tag = b64url_encode(tag_bytes[:8])
    with pytest.raises((InvalidTag, ValueError)):
        em.decrypt(env)


# ── Cipher suite invariant tests ──────────────────────────────────────────────

def test_already_encrypted_raises():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    with pytest.raises(ValueError, match="already encrypted"):
        em.encrypt(env)


def test_decrypt_plaintext_envelope_raises():
    _, env = _make_env()
    em = EncryptionManager.generate()
    with pytest.raises(ValueError, match="not encrypted"):
        em.decrypt(env)


def test_schema_plaintext_with_iv_fails():
    """cipher_suite=None but iv present → schema violation."""
    _, env = _make_env()
    env.iv = "somevalue"
    result = env.collect_schema_errors()
    assert not result
    assert any("iv" in e for e in result.errors)


def test_schema_encrypted_missing_auth_tag_fails():
    _, env = _make_env()
    em = EncryptionManager.generate()
    em.encrypt(env)
    env.auth_tag = None  # remove auth_tag
    result = env.collect_schema_errors()
    assert not result
    assert any("auth_tag" in e for e in result.errors)


def test_schema_plaintext_payload_not_dict_fails():
    _, env = _make_env()
    env.payload = "not-a-dict"
    result = env.collect_schema_errors()
    assert not result
    assert any("payload" in e for e in result.errors)


# ── Backward compatibility ────────────────────────────────────────────────────

def test_backward_compat_old_ledger_no_cipher_suite(tmp_path):
    """Ledgers without cipher_suite field replay cleanly."""
    km = Ed25519KeyManager.generate()
    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(3):
        ledger.emit("execution", {"step": i})

    summary = ReplayEngine(mode="strict").stream_verify(Path(ledger.get_path()))
    assert summary.chain_valid
    assert summary.verified_count == 4  # genesis + 3


def test_encrypted_ledger_verifies_without_decryption(tmp_path):
    """ReplayEngine verifies encrypted ledger without EncryptionManager."""
    km = Ed25519KeyManager.generate()
    em = EncryptionManager.generate()
    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for i in range(3):
        ledger.emit("execution", {"step": i}, encrypt=True, encryption_manager=em)

    summary = ReplayEngine(mode="strict").stream_verify(Path(ledger.get_path()))
    assert summary.chain_valid


def test_mixed_encrypted_and_plaintext_ledger(tmp_path):
    """Ledger with some encrypted and some plaintext records verifies cleanly."""
    km = Ed25519KeyManager.generate()
    em = EncryptionManager.generate()
    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    ledger.emit("execution", {"step": 0})                                      # plaintext
    ledger.emit("execution", {"step": 1}, encrypt=True, encryption_manager=em) # encrypted
    ledger.emit("execution", {"step": 2})                                      # plaintext
    ledger.emit("execution", {"step": 3}, encrypt=True, encryption_manager=em) # encrypted

    summary = ReplayEngine(mode="strict").stream_verify(Path(ledger.get_path()))
    assert summary.chain_valid


# ── Full ledger round-trip ────────────────────────────────────────────────────

def test_full_ledger_encrypt_decrypt_roundtrip(tmp_path):
    """Emit encrypted records, read back from disk, decrypt each."""
    km = Ed25519KeyManager.generate()
    em = EncryptionManager.generate()
    payloads = [{"step": i, "data": f"sensitive-{i}"} for i in range(3)]

    ledger = GEFLedger(km, "test-agent", ledger_path=str(tmp_path))
    for p in payloads:
        ledger.emit("execution", p, encrypt=True, encryption_manager=em)

    # Read back from disk
    ledger_path = Path(ledger.get_path())
    recovered = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            d = json.loads(line)
            env = ExecutionEnvelope.from_dict(d)
            if env.cipher_suite == 1:
                recovered.append(em.decrypt(env))

    assert recovered == payloads
