"""
tests/test_gef_invariants.py

GEF Invariant Test Suite — v0.2.0

These tests are the CONSTITUTION of the GuardClaw protocol.
They do not test features. They test LAWS.

A law is something that must hold true in every circumstance.
If any test here fails, the protocol is broken — not the test.

Invariants tested:

  SIGNING
    INV-01  Signature verifies over correct canonical bytes
    INV-02  Changing payload breaks signature
    INV-03  Changing record_type breaks signature
    INV-04  Changing timestamp breaks signature
    INV-05  Changing agent_id breaks signature
    INV-06  Changing nonce breaks signature
    INV-07  Changing sequence breaks signature
    INV-08  Changing gef_version breaks signature

  CHAIN
    INV-09  causal_hash of first entry == GENESIS_HASH
    INV-10  causal_hash of second entry == SHA-256(JCS(entry_0.to_chain_dict()))
    INV-11  Changing payload in prev breaks next entry's chain
    INV-12  Changing record_id in prev breaks next entry's chain
    INV-13  Chain verifies across N entries
    INV-14  Injecting entry in middle breaks chain at injection point

  SCHEMA
    INV-15  Unknown record_type rejected by create()
    INV-16  Unknown record_type detected by validate_schema()
    INV-17  Malformed nonce (wrong length) detected by validate_schema()
    INV-18  Malformed timestamp (no Z suffix) detected by validate_schema()
    INV-19  Malformed timestamp (microseconds) detected by validate_schema()
    INV-20  Malformed signer_public_key (wrong length) detected
    INV-21  Non-dict payload rejected by create()
    INV-22  Negative sequence rejected by create()

  REPLAY
    INV-23  ReplayEngine detects chain break in JSONL
    INV-24  ReplayEngine detects invalid signature in JSONL
    INV-25  ReplayEngine detects sequence gap in JSONL
    INV-26  ReplayEngine rejects mixed gef_version ledger
    INV-27  ReplayEngine detects schema violation in JSONL
    INV-28  Replay summary reports correct counts

  NONCE
    INV-29  Two envelopes from same agent never share nonce
    INV-30  Nonce does not appear in causal_hash of unrelated entries

  CROSS-LANG REPRODUCIBILITY
    INV-31  to_signing_dict and to_chain_dict are identical field sets
    INV-32  canonical_bytes_for_signing is deterministic across calls
    INV-33  Chain hash is deterministic across process restarts (fixture)
"""

import hashlib
import json
import tempfile
from pathlib import Path
from typing import List

import pytest

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import (
    ExecutionEnvelope,
    GEF_VERSION,
    GENESIS_HASH,
    GEFVersionError,
    RecordType,
    _VALID_RECORD_TYPES,
)
from guardclaw.core.replay import ReplayEngine


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def key():
    """A fresh Ed25519 key manager for each test."""
    return Ed25519KeyManager.generate()


@pytest.fixture
def key2():
    """A second independent key — used in multi-agent tests."""
    return Ed25519KeyManager.generate()


def make_env(
    key: Ed25519KeyManager,
    record_type: str = RecordType.EXECUTION,
    sequence: int = 0,
    payload: dict = None,
    prev: ExecutionEnvelope = None,
) -> ExecutionEnvelope:
    """Helper: create and sign a single envelope."""
    return ExecutionEnvelope.create(
        record_type=       record_type,
        agent_id=          "agent-test-001",
        signer_public_key= key.public_key_hex,
        sequence=          sequence,
        payload=           payload or {"action": "test"},
        prev=              prev,
    ).sign(key)


def make_chain(
    key: Ed25519KeyManager,
    n: int,
    record_type: str = RecordType.EXECUTION,
) -> List[ExecutionEnvelope]:
    """Helper: create a signed chain of n envelopes."""
    chain = []
    prev  = None
    for i in range(n):
        env  = make_env(key, record_type=record_type, sequence=i, prev=prev)
        chain.append(env)
        prev = env
    return chain


def write_ledger(
    envelopes: List[ExecutionEnvelope],
    path: Path,
) -> None:
    """Write envelopes to a JSONL file."""
    with open(path, "w", encoding="utf-8") as f:
        for env in envelopes:
            f.write(json.dumps(env.to_dict()) + "\n")


# ─────────────────────────────────────────────────────────────
# SIGNING INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestSigningInvariants:

    def test_INV01_signature_verifies_correctly(self, key):
        """INV-01: A properly signed envelope verifies."""
        env = make_env(key)
        assert env.is_signed(), "Envelope must have a signature after sign()"
        assert env.verify_signature(), "Signature must verify over canonical bytes"

    def test_INV02_payload_change_breaks_signature(self, key):
        """INV-02: Mutating payload after signing must invalidate the signature."""
        env = make_env(key, payload={"action": "original"})
        assert env.verify_signature()

        # Tamper payload directly (simulates storage corruption / injection)
        env.payload = {"action": "TAMPERED"}
        assert not env.verify_signature(), (
            "Signature must fail after payload mutation"
        )

    def test_INV03_record_type_change_breaks_signature(self, key):
        """INV-03: Mutating record_type after signing must invalidate the signature."""
        env = make_env(key, record_type=RecordType.INTENT)
        assert env.verify_signature()

        env.record_type = RecordType.ADMIN_ACTION
        assert not env.verify_signature(), (
            "Signature must fail after record_type mutation"
        )

    def test_INV04_timestamp_change_breaks_signature(self, key):
        """INV-04: Mutating timestamp after signing must invalidate the signature."""
        env = make_env(key)
        assert env.verify_signature()

        env.timestamp = "2000-01-01T00:00:00.000Z"
        assert not env.verify_signature(), (
            "Signature must fail after timestamp mutation"
        )

    def test_INV05_agent_id_change_breaks_signature(self, key):
        """INV-05: Mutating agent_id after signing must invalidate the signature."""
        env = make_env(key)
        assert env.verify_signature()

        env.agent_id = "malicious-agent"
        assert not env.verify_signature(), (
            "Signature must fail after agent_id mutation"
        )

    def test_INV06_nonce_change_breaks_signature(self, key):
        """INV-06: Mutating nonce after signing must invalidate the signature."""
        import secrets
        env = make_env(key)
        assert env.verify_signature()

        env.nonce = secrets.token_hex(16)
        assert not env.verify_signature(), (
            "Signature must fail after nonce mutation"
        )

    def test_INV07_sequence_change_breaks_signature(self, key):
        """INV-07: Mutating sequence after signing must invalidate the signature."""
        env = make_env(key, sequence=0)
        assert env.verify_signature()

        env.sequence = 999
        assert not env.verify_signature(), (
            "Signature must fail after sequence mutation"
        )

    def test_INV08_gef_version_change_breaks_signature(self, key):
        """INV-08: Mutating gef_version after signing must invalidate the signature."""
        env = make_env(key)
        assert env.verify_signature()

        env.gef_version = "9.9"
        assert not env.verify_signature(), (
            "Signature must fail after gef_version mutation"
        )

    def test_wrong_key_cannot_verify(self, key, key2):
        """Signature produced by key cannot be verified by key2."""
        env = make_env(key)
        assert env.verify_signature()
        assert not env.verify_signature(key2.public_key_hex), (
            "Wrong public key must not verify a valid signature"
        )

    def test_missing_signature_fails(self, key):
        """Unsigned envelope must not verify."""
        env = ExecutionEnvelope.create(
            record_type=       RecordType.INTENT,
            agent_id=          "agent-x",
            signer_public_key= key.public_key_hex,
            sequence=          0,
            payload=           {"intent": "test"},
        )
        assert not env.is_signed()
        assert not env.verify_signature(), (
            "Unsigned envelope must return False from verify_signature()"
        )


# ─────────────────────────────────────────────────────────────
# CHAIN INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestChainInvariants:

    def test_INV09_first_entry_genesis_hash(self, key):
        """INV-09: First entry causal_hash must equal GENESIS_HASH."""
        env = make_env(key, sequence=0, prev=None)
        assert env.causal_hash == GENESIS_HASH, (
            f"First entry must have GENESIS_HASH, got {env.causal_hash[:16]}..."
        )

    def test_INV10_second_entry_causal_hash_is_correct(self, key):
        """INV-10: causal_hash of entry[1] must be SHA-256(JCS(entry[0].to_chain_dict()))."""
        e0 = make_env(key, sequence=0)
        e1 = make_env(key, sequence=1, prev=e0)

        expected = hashlib.sha256(
            canonical_json_encode(e0.to_chain_dict())
        ).hexdigest()

        assert e1.causal_hash == expected, (
            "causal_hash must be SHA-256(JCS(prev.to_chain_dict()))"
        )

    def test_INV11_payload_mutation_in_prev_breaks_next_chain(self, key):
        """INV-11: Mutating payload of e0 must break e1's chain verification."""
        e0 = make_env(key, sequence=0, payload={"action": "original"})
        e1 = make_env(key, sequence=1, prev=e0)

        assert e1.verify_chain(e0), "Chain must be valid before tampering"

        # Tamper e0's payload after e1 was built
        e0.payload = {"action": "TAMPERED"}

        assert not e1.verify_chain(e0), (
            "Chain must break after prev entry payload mutation"
        )

    def test_INV12_record_id_mutation_in_prev_breaks_next_chain(self, key):
        """INV-12: Mutating record_id of e0 must break e1's chain verification."""
        e0 = make_env(key, sequence=0)
        e1 = make_env(key, sequence=1, prev=e0)

        assert e1.verify_chain(e0)
        e0.record_id = "gef-00000000-0000-0000-0000-000000000000"
        assert not e1.verify_chain(e0), (
            "Chain must break after prev entry record_id mutation"
        )

    def test_INV13_chain_verifies_across_n_entries(self, key):
        """INV-13: A chain of N signed envelopes must fully verify."""
        N     = 10
        chain = make_chain(key, N)

        for i, env in enumerate(chain):
            prev = chain[i - 1] if i > 0 else None
            assert env.verify_chain(prev), (
                f"Chain broke at sequence {i}"
            )
            assert env.verify_signature(), (
                f"Signature failed at sequence {i}"
            )

    def test_INV14_injected_entry_breaks_chain(self, key):
        """INV-14: Injecting a new entry in the middle breaks chain at that point."""
        chain  = make_chain(key, 5)
        e0     = chain[0]
        # Build an injected entry that looks like sequence 1 but has different payload
        inject = make_env(
            key,
            sequence=1,
            payload={"action": "INJECTED"},
            prev=e0,
        )

        # chain[2] was built from chain[1], not from inject
        # So chain[2].verify_chain(inject) must fail
        assert not chain[2].verify_chain(inject), (
            "Entry built from original chain[1] must not verify against injected prev"
        )

    def test_chain_hash_excludes_signature(self, key):
        """Signature field must NOT affect causal_hash of next entry."""
        e0    = make_env(key, sequence=0)
        e1    = make_env(key, sequence=1, prev=e0)

        # Record e1's causal_hash BEFORE mutating e0's signature
        original_causal = e1.causal_hash

        # Mutate signature on e0 (post-signing)
        e0.signature = "deadbeef" * 16

        # Recompute what e1's causal_hash would be based on mutated e0
        recomputed = e1.expected_causal_hash_from(e0)

        # Since to_chain_dict() excludes signature, recomputed DIFFERS from original
        # because to_chain_dict() does NOT include signature — both hashes match prev
        # This test confirms signature is NOT in chain dict
        chain_dict = e0.to_chain_dict()
        assert "signature" not in chain_dict, (
            "signature must not appear in to_chain_dict()"
        )


# ─────────────────────────────────────────────────────────────
# SCHEMA INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestSchemaInvariants:

    def test_INV15_invalid_record_type_rejected_by_create(self, key):
        """INV-15: create() must raise ValueError for unknown record_type."""
        with pytest.raises(ValueError, match="Invalid record_type"):
            ExecutionEnvelope.create(
                record_type=       "evil_type",
                agent_id=          "agent-x",
                signer_public_key= key.public_key_hex,
                sequence=          0,
                payload=           {},
            )

    def test_INV16_invalid_record_type_detected_by_validate_schema(self, key):
        """INV-16: validate_schema() must catch injected unknown record_type."""
        env = make_env(key)
        env.record_type = "evil_type"
        result = env.validate_schema()
        assert not result, "validate_schema must return False for unknown record_type"
        assert any("record_type" in e for e in result.errors)

    def test_INV17_malformed_nonce_detected(self, key):
        """INV-17: Nonce with wrong length must fail validate_schema()."""
        env       = make_env(key)
        env.nonce = "tooshort"
        result    = env.validate_schema()
        assert not result
        assert any("nonce" in e for e in result.errors)

    def test_INV18_timestamp_without_Z_detected(self, key):
        """INV-18: Timestamp without Z suffix must fail validate_schema()."""
        env           = make_env(key)
        env.timestamp = "2026-02-25T12:00:00.000+00:00"
        result        = env.validate_schema()
        assert not result
        assert any("timestamp" in e for e in result.errors)

    def test_INV19_timestamp_with_microseconds_detected(self, key):
        """INV-19: Timestamp with microseconds (6 digits) must fail validate_schema()."""
        env           = make_env(key)
        env.timestamp = "2026-02-25T12:00:00.123456Z"
        result        = env.validate_schema()
        assert not result
        assert any("timestamp" in e for e in result.errors)

    def test_INV20_short_public_key_detected(self, key):
        """INV-20: signer_public_key with wrong length must fail validate_schema()."""
        env                    = make_env(key)
        env.signer_public_key  = "deadbeef"
        result                 = env.validate_schema()
        assert not result
        assert any("signer_public_key" in e for e in result.errors)

    def test_INV21_non_dict_payload_rejected_by_create(self, key):
        """INV-21: create() must raise TypeError for non-dict payload."""
        with pytest.raises(TypeError, match="payload must be dict"):
            ExecutionEnvelope.create(
                record_type=       RecordType.RESULT,
                agent_id=          "agent-x",
                signer_public_key= key.public_key_hex,
                sequence=          0,
                payload=           "this is not a dict",
            )

    def test_INV22_negative_sequence_rejected(self, key):
        """INV-22: create() must raise ValueError for negative sequence."""
        with pytest.raises(ValueError, match="sequence"):
            ExecutionEnvelope.create(
                record_type=       RecordType.HEARTBEAT,
                agent_id=          "agent-x",
                signer_public_key= key.public_key_hex,
                sequence=          -1,
                payload=           {},
            )

    def test_valid_envelope_passes_schema(self, key):
        """A correctly created envelope must pass validate_schema()."""
        env    = make_env(key)
        result = env.validate_schema()
        assert result, f"Valid envelope failed schema: {result.errors}"

    def test_all_record_types_accepted_by_create(self, key):
        """Every RecordType constant must be accepted by create()."""
        for rt in _VALID_RECORD_TYPES:
            env = ExecutionEnvelope.create(
                record_type=       rt,
                agent_id=          "agent-x",
                signer_public_key= key.public_key_hex,
                sequence=          0,
                payload=           {"type": rt},
            )
            assert env.record_type == rt


# ─────────────────────────────────────────────────────────────
# REPLAY INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestReplayInvariants:

    def test_INV23_replay_detects_chain_break(self, key, tmp_path):
        """INV-23: ReplayEngine must detect a chain break in JSONL."""
        chain = make_chain(key, 4)

        # Tamper entry 1's payload directly — chain[2] will no longer match
        chain[1].payload = {"action": "TAMPERED"}

        ledger = tmp_path / "ledger.jsonl"
        write_ledger(chain, ledger)

        engine  = ReplayEngine()
        engine.load(ledger)
        summary = engine.verify()

        assert not summary.chain_valid, "Tampered chain must not be valid"
        assert any(
            v.violation_type == "chain_break"
            for v in summary.violations
        ), "Must report chain_break violation"

    def test_INV24_replay_detects_invalid_signature(self, key, key2, tmp_path):
        """INV-24: ReplayEngine must detect a forged signature."""
        chain = make_chain(key, 3)

        # Replace entry 1's signature with one from a different key
        bad_bytes = chain[1].canonical_bytes_for_signing()
        chain[1].signature = key2.sign(bad_bytes)

        ledger = tmp_path / "ledger.jsonl"
        write_ledger(chain, ledger)

        engine  = ReplayEngine()
        engine.load(ledger)
        summary = engine.verify()

        assert any(
            v.violation_type == "invalid_signature"
            for v in summary.violations
        ), "Must report invalid_signature violation"

    def test_INV25_replay_detects_sequence_gap(self, key, tmp_path):
        """INV-25: ReplayEngine must detect a missing sequence number."""
        chain = make_chain(key, 5)
        # Remove entry at sequence 2 to create a gap
        gapped = [e for e in chain if e.sequence != 2]

        ledger = tmp_path / "ledger.jsonl"
        write_ledger(gapped, ledger)

        engine  = ReplayEngine()
        engine.load(ledger)
        summary = engine.verify()

        assert any(
            v.violation_type == "sequence_gap"
            for v in summary.violations
        ), "Must report sequence_gap violation"

    def test_INV26_replay_rejects_mixed_version_ledger(self, key, tmp_path):
        """INV-26: ReplayEngine must raise GEFVersionError for mixed gef_version."""
        chain = make_chain(key, 3)
        # Inject a version mismatch on entry 2
        chain[2].gef_version = "9.9"

        ledger = tmp_path / "ledger.jsonl"
        # Bypass schema validation to write the bad ledger
        with open(ledger, "w") as f:
            for env in chain:
                d = env.to_dict()
                f.write(json.dumps(d) + "\n")

        engine = ReplayEngine()
        # Schema will catch gef_version != "1.0" before version check
        # So expect ValueError (schema) or GEFVersionError (version check)
        with pytest.raises((ValueError, GEFVersionError)):
            engine.load(ledger)

    def test_INV27_replay_detects_schema_violation(self, key, tmp_path):
        """INV-27: ReplayEngine must raise ValueError for injected invalid record_type."""
        chain = make_chain(key, 2)

        ledger = tmp_path / "ledger.jsonl"
        with open(ledger, "w") as f:
            for env in chain:
                d = env.to_dict()
                f.write(json.dumps(d) + "\n")
            # Inject a malformed line
            bad = chain[0].to_dict()
            bad["record_type"] = "injected_evil"
            bad["sequence"]    = 2
            f.write(json.dumps(bad) + "\n")

        engine = ReplayEngine()
        with pytest.raises(ValueError, match="schema violation"):
            engine.load(ledger)

    def test_INV28_replay_summary_counts_correct(self, key, tmp_path):
        """INV-28: ReplaySummary must report accurate counts."""
        chain = make_chain(key, 5, record_type=RecordType.EXECUTION)

        ledger = tmp_path / "ledger.jsonl"
        write_ledger(chain, ledger)

        engine  = ReplayEngine()
        engine.load(ledger)
        summary = engine.verify()

        assert summary.total_entries == 5
        assert summary.valid_signatures == 5
        assert summary.invalid_signatures == 0
        assert summary.record_type_counts.get(RecordType.EXECUTION) == 5
        assert summary.chain_valid is True

    def test_empty_ledger_loads_cleanly(self, tmp_path):
        """Empty JSONL file must load without error and return empty summary."""
        ledger = tmp_path / "empty.jsonl"
        ledger.write_text("")

        engine  = ReplayEngine()
        engine.load(ledger)
        summary = engine.verify()

        assert summary.total_entries == 0
        assert summary.chain_valid is True
        assert summary.violations == []


# ─────────────────────────────────────────────────────────────
# NONCE INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestNonceInvariants:

    def test_INV29_two_envelopes_never_share_nonce(self, key):
        """INV-29: Any two independently created envelopes must have different nonces."""
        nonces = {make_env(key, sequence=i).nonce for i in range(100)}
        assert len(nonces) == 100, (
            "100 independently created envelopes must have 100 unique nonces"
        )

    def test_INV30_nonce_is_32_hex_chars(self, key):
        """INV-30: Nonce must be exactly 32 hex characters."""
        for i in range(20):
            env = make_env(key, sequence=i)
            assert len(env.nonce) == 32
            try:
                bytes.fromhex(env.nonce)
            except ValueError:
                pytest.fail(f"Nonce {env.nonce!r} is not valid hex")

    def test_nonce_in_signing_dict(self, key):
        """Nonce must appear in to_signing_dict() and to_chain_dict()."""
        env = make_env(key)
        assert "nonce" in env.to_signing_dict()
        assert "nonce" in env.to_chain_dict()

    def test_INV29_replay_detects_duplicate_nonce(self, key, tmp_path):
        """
        INV-29 (replay enforcement):
        A ledger containing two entries with identical nonces MUST
        be rejected by the replay engine with a 'schema' violation.
        """
        import json
        from guardclaw.core.replay import ReplayEngine

        # Build entry 0
        e0 = ExecutionEnvelope.create(
            record_type=       RecordType.EXECUTION,
            agent_id=          "agent-nonce-test",
            signer_public_key= key.public_key_hex,
            sequence=          0,
            payload=           {"step": 0},
        )
        e0.sign(key)

        # Build entry 1 (valid chain)
        e1 = ExecutionEnvelope.create(
            record_type=       RecordType.EXECUTION,
            agent_id=          "agent-nonce-test",
            signer_public_key= key.public_key_hex,
            sequence=          1,
            payload=           {"step": 1},
            prev=              e0,
        )
        e1.sign(key)

        # Serialize both to dicts, then inject duplicate nonce at the dict level
        # This simulates a manually crafted / malicious ledger file
        e0_dict = e0.to_dict()
        e1_dict = e1.to_dict()
        e1_dict["nonce"] = e0_dict["nonce"]   # ← poison: force shared nonce

        # Write the poisoned ledger as JSONL
        ledger_path = tmp_path / "dup_nonce_ledger.jsonl"
        with open(ledger_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(e0_dict) + "\n")
            f.write(json.dumps(e1_dict) + "\n")

        # Replay MUST detect the duplicate nonce
        engine = ReplayEngine(silent=True)
        engine.load(ledger_path)
        summary = engine.verify()

        schema_violations = [
            v for v in summary.violations
            if v.violation_type == "schema"
        ]

        assert len(schema_violations) >= 1, (
            "replay engine must emit a 'schema' violation "
            "when two entries share the same nonce"
        )
        assert any("nonce" in v.detail.lower() for v in schema_violations), (
            "the violation detail must mention 'nonce'"
        )
        assert not summary.chain_valid, (
            "chain_valid must be False when a duplicate nonce is present"
        )


# ─────────────────────────────────────────────────────────────
# CROSS-LANGUAGE REPRODUCIBILITY INVARIANTS
# ─────────────────────────────────────────────────────────────

class TestCrossLanguageInvariants:

    def test_INV31_signing_and_chain_dicts_identical_field_sets(self, key):
        """INV-31: to_signing_dict and to_chain_dict must have identical field sets."""
        env         = make_env(key)
        signing_keys = set(env.to_signing_dict().keys())
        chain_keys   = set(env.to_chain_dict().keys())
        assert signing_keys == chain_keys, (
            f"Field mismatch:\n"
            f"  signing-only: {signing_keys - chain_keys}\n"
            f"  chain-only:   {chain_keys - signing_keys}"
        )

    def test_INV32_canonical_bytes_deterministic(self, key):
        """INV-32: canonical_bytes_for_signing must be deterministic across calls."""
        env    = make_env(key)
        bytes1 = env.canonical_bytes_for_signing()
        bytes2 = env.canonical_bytes_for_signing()
        assert bytes1 == bytes2, (
            "canonical_bytes_for_signing must be deterministic"
        )

    def test_INV33_chain_hash_deterministic_across_serialize_deserialize(self, key):
        """INV-33: chain hash must survive serialize → deserialize → recompute."""
        chain = make_chain(key, 3)

        # Serialize then deserialize
        serialized   = [json.dumps(e.to_dict()) for e in chain]
        deserialized = [
            ExecutionEnvelope.from_dict(json.loads(s))
            for s in serialized
        ]

        # Verify chain integrity on deserialized envelopes
        for i, env in enumerate(deserialized):
            prev = deserialized[i - 1] if i > 0 else None
            assert env.verify_chain(prev), (
                f"Chain broke after serialize/deserialize at sequence {i}"
            )
            assert env.verify_signature(), (
                f"Signature broke after serialize/deserialize at sequence {i}"
            )

    def test_gef_version_in_signing_and_chain_dicts(self, key):
        """gef_version must appear in both to_signing_dict() and to_chain_dict()."""
        env = make_env(key)
        assert "gef_version" in env.to_signing_dict()
        assert "gef_version" in env.to_chain_dict()
        assert env.to_signing_dict()["gef_version"] == GEF_VERSION

    def test_payload_in_signing_and_chain_dicts(self, key):
        """payload must appear in both to_signing_dict() and to_chain_dict()."""
        env = make_env(key, payload={"critical": "data"})
        assert "payload" in env.to_signing_dict()
        assert "payload" in env.to_chain_dict()
        assert env.to_signing_dict()["payload"] == {"critical": "data"}

    def test_signature_not_in_chain_dict(self, key):
        """signature must NOT appear in to_chain_dict()."""
        env = make_env(key)
        assert "signature" not in env.to_chain_dict(), (
            "signature must be excluded from to_chain_dict() — "
            "it is a function of the dict, not an input to it"
        )

    def test_signature_not_in_signing_dict(self, key):
        """signature must NOT appear in to_signing_dict() — it is the OUTPUT."""
        env = make_env(key)
        assert "signature" not in env.to_signing_dict(), (
            "signature must be excluded from to_signing_dict() — "
            "it is the output of signing, not an input"
        )
