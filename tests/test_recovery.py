"""
tests/test_recovery.py  —  GuardClaw Adversarial Test Suite v0.7.2

Covers:
    - Pre-flight failures
    - Genesis enforcement
    - total_entries semantics
    - recovery_mode_active semantics
    - malformed JSON
    - schema violations
    - missing_field:<exact_key> format
    - signature failures
    - chain violations
    - FILE-TRUTH: failure_sequence = line_num
    - boundary hash reproducibility
    - cold verification
"""

from __future__ import annotations

import hashlib
import json

import pytest

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.failure import (
    FailureDetail,
    FailureType,
    ProtocolInvariantError,
    VerificationSummary,
    compute_boundary_hash,
)
from guardclaw.core.models import ExecutionEnvelope, RecordType
from guardclaw.core.replay import ReplayEngine


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_key():
    return Ed25519KeyManager.generate()


def _make_chain(key, count=5, agent_id="test-agent", start_record_type=RecordType.GENESIS):
    """Build a valid chain. First entry uses start_record_type (default GENESIS)."""
    chain = []
    prev = None
    for i in range(count):
        rtype = start_record_type if i == 0 else RecordType.EXECUTION
        env = ExecutionEnvelope.create(
            record_type=rtype,
            agent_id=agent_id,
            signer_public_key=key.public_key_hex,
            sequence=i,
            payload={"step": i},
            prev=prev,
        ).sign(key)
        chain.append(env)
        prev = env
    return chain


def _write_jsonl(path, envelopes):
    with open(path, "w", encoding="utf-8") as f:
        for e in envelopes:
            f.write(json.dumps(e.to_dict()) + "\n")


def _write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def strict(path):
    return ReplayEngine(mode="strict", silent=True).stream_verify(path)


def recovery(path):
    return ReplayEngine(mode="recovery", silent=True).stream_verify(path)


# ── Pre-flight ────────────────────────────────────────────────────────────────

class TestPreFlight:

    def test_missing_file_strict(self, tmp_path):
        s = strict(tmp_path / "no.jsonl")
        assert not s.chain_valid
        assert s.failure_type == FailureType.LEDGER_INVALID
        assert s.failure_detail == FailureDetail.FILE_NOT_FOUND
        assert s.integrity_boundary_hash is None

    def test_missing_file_recovery(self, tmp_path):
        s = recovery(tmp_path / "no.jsonl")
        assert not s.chain_valid
        assert s.recovery_mode_active
        assert s.failure_type == FailureType.LEDGER_INVALID
        assert s.failure_detail == FailureDetail.FILE_NOT_FOUND
        assert s.integrity_boundary_hash is None

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        s = strict(p)
        assert not s.chain_valid
        assert s.failure_type == FailureType.LEDGER_INVALID
        assert s.failure_detail == FailureDetail.EMPTY_LEDGER
        assert s.integrity_boundary_hash is None

    def test_invariant_1(self):
        with pytest.raises(ProtocolInvariantError, match="Invariant 1"):
            VerificationSummary(
                total_entries=0,
                chain_valid=True,
                recovery_mode_active=True,
                partial_integrity=True,
            )

    def test_invariant_2(self):
        with pytest.raises(ProtocolInvariantError, match="Invariant 2"):
            VerificationSummary(
                total_entries=0,
                chain_valid=False,
            )

    def test_invariant_3(self):
        with pytest.raises(ProtocolInvariantError, match="Invariant 3"):
            VerificationSummary(
                total_entries=0,
                chain_valid=False,
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.FILE_NOT_FOUND,
                integrity_boundary_hash="a" * 64,
            )


# ── Genesis enforcement ───────────────────────────────────────────────────────

class TestGenesisEnforcement:

    def test_non_genesis_first_entry_strict(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3, start_record_type=RecordType.EXECUTION)
        p = tmp_path / "no_genesis.jsonl"
        _write_jsonl(p, chain)

        s = strict(p)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.GENESIS_MISSING
        assert s.failure_sequence == 0

    def test_non_genesis_first_entry_recovery(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3, start_record_type=RecordType.EXECUTION)
        p = tmp_path / "no_genesis.jsonl"
        _write_jsonl(p, chain)

        s = recovery(p)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.GENESIS_MISSING
        assert s.verified_count == 0
        assert s.integrity_boundary_hash is None

    def test_valid_genesis_first_entry_passes(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5, start_record_type=RecordType.GENESIS)
        p = tmp_path / "valid.jsonl"
        _write_jsonl(p, chain)

        s = strict(p)
        assert s.chain_valid

    def test_genesis_at_line_0_only(self, tmp_path):
        """
        A GENESIS record inserted later in the chain should not trigger the
        first-entry genesis rule. Here we tamper with record_type at seq 3
        without re-signing, so signature validation should fail.
        """
        key = _make_key()
        chain = _make_chain(key, count=5, start_record_type=RecordType.GENESIS)

        d = chain[3].to_dict()
        d["record_type"] = RecordType.GENESIS
        # DO NOT re-sign

        lines = [
            json.dumps(chain[0].to_dict()),
            json.dumps(chain[1].to_dict()),
            json.dumps(chain[2].to_dict()),
            json.dumps(d),
        ]
        p = tmp_path / "double_genesis.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_INVALID
        assert s.failure_sequence == 3


# ── total_entries correctness ─────────────────────────────────────────────────

class TestTotalEntriesCorrectness:

    def test_total_entries_on_failure_at_line_2(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=100)
        lines = [json.dumps(e.to_dict()) for e in chain]

        key2 = _make_key()
        bad = chain[2].to_dict()
        bad["signature"] = key2.sign(chain[2].canonical_bytes_for_signing())
        lines[2] = json.dumps(bad)

        p = tmp_path / "fail2.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert not s.chain_valid
        assert s.failure_sequence == 2
        assert s.total_entries == 3

    def test_total_entries_valid_chain(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=20)
        p = tmp_path / "valid.jsonl"
        _write_jsonl(p, chain)

        s = strict(p)
        assert s.total_entries == 20

    def test_total_entries_recovery_failure_at_line_5(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=10)
        lines = [json.dumps(e.to_dict()) for e in chain]
        lines[5] = "{BAD JSON}"

        p = tmp_path / "fail5.jsonl"
        _write_lines(p, lines)

        s = recovery(p)
        assert s.failure_sequence == 5
        assert s.total_entries == 6

    def test_total_entries_bad_line_0(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        _write_lines(p, ["{BAD}"])

        s = strict(p)
        assert s.total_entries == 1


# ── recovery_mode_active semantics ───────────────────────────────────────────

class TestRecoveryModeActive:

    def test_recovery_mode_active_on_valid_chain(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=10)
        p = tmp_path / "valid.jsonl"
        _write_jsonl(p, chain)

        s = recovery(p)
        assert s.chain_valid
        assert s.recovery_mode_active
        assert not s.partial_integrity

    def test_recovery_mode_active_on_failure(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5)
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BAD}"]
        p = tmp_path / "fail.jsonl"
        _write_lines(p, lines)

        s = recovery(p)
        assert not s.chain_valid
        assert s.recovery_mode_active

    def test_strict_mode_active_is_false(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5)
        p = tmp_path / "valid.jsonl"
        _write_jsonl(p, chain)

        s = strict(p)
        assert not s.recovery_mode_active


# ── Malformed JSON ────────────────────────────────────────────────────────────

class TestMalformedJSON:

    def test_bad_json_line_0(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        _write_lines(p, ["{NOT JSON}"])
        s = strict(p)
        assert s.failure_type == FailureType.MALFORMED_JSON
        assert s.failure_sequence == 0

    def test_bad_json_line_3(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3)
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BAD}"]
        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)
        s = strict(p)
        assert s.failure_type == FailureType.MALFORMED_JSON
        assert s.failure_sequence == 3

    def test_bad_json_recovery_boundary(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3)
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BAD}"]
        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)
        s = recovery(p)
        assert s.verified_count == 3
        assert s.failure_sequence == 3
        assert s.integrity_boundary_hash == compute_boundary_hash(chain[2])


# ── Schema violations ─────────────────────────────────────────────────────────

class TestSchemaViolations:

    def test_missing_causal_hash(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=1)
        d = chain[0].to_dict()
        del d["causal_hash"]

        p = tmp_path / "bad.jsonl"
        _write_lines(p, [json.dumps(d)])

        s = strict(p)
        assert s.failure_type == FailureType.SCHEMA_VIOLATION
        assert s.failure_detail == "missing_field:causal_hash"

    def test_null_signature(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=1)
        d = chain[0].to_dict()
        d["signature"] = None

        p = tmp_path / "bad.jsonl"
        _write_lines(p, [json.dumps(d)])

        s = strict(p)
        assert s.failure_type == FailureType.SCHEMA_VIOLATION
        assert s.failure_detail == FailureDetail.MISSING_SIGNATURE


# ── missing_field:<exact_key> format ─────────────────────────────────────────

class TestMissingFieldFormat:

    GEF_REQUIRED_FIELDS = [
        "gef_version",
        "record_id",
        "record_type",
        "agent_id",
        "signer_public_key",
        "sequence",
        "nonce",
        "timestamp",
        "causal_hash",
    ]

    @pytest.mark.parametrize("field", GEF_REQUIRED_FIELDS)
    def test_missing_field_exact_key(self, tmp_path, field):
        key = _make_key()
        chain = _make_chain(key, count=1)
        d = chain[0].to_dict()
        del d[field]

        p = tmp_path / f"miss_{field}.jsonl"
        _write_lines(p, [json.dumps(d)])

        s = strict(p)
        assert s.failure_type == FailureType.SCHEMA_VIOLATION
        assert s.failure_detail == f"missing_field:{field}"


# ── Signature failures ────────────────────────────────────────────────────────

class TestSignatureFailures:

    def test_sig_encoding_padding(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=1)
        d = chain[0].to_dict()
        d["signature"] += "=="

        p = tmp_path / "bad.jsonl"
        _write_lines(p, [json.dumps(d)])

        s = strict(p)
        assert s.failure_type == FailureType.SIGNATURE_ENCODING_INVALID
        assert s.failure_detail == FailureDetail.INVALID_BASE64URL

    def test_sig_wrong_key(self, tmp_path):
        key1 = _make_key()
        key2 = _make_key()
        chain = _make_chain(key1, count=1)
        d = chain[0].to_dict()
        d["signature"] = key2.sign(chain[0].canonical_bytes_for_signing())

        p = tmp_path / "bad.jsonl"
        _write_lines(p, [json.dumps(d)])

        s = strict(p)
        assert s.failure_type == FailureType.SIGNATURE_INVALID
        assert s.failure_detail == FailureDetail.ED25519_FAILED


# ── Chain violations ──────────────────────────────────────────────────────────

class TestChainViolations:

    def test_sequence_gap(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3)
        lines = [json.dumps(chain[0].to_dict()), json.dumps(chain[2].to_dict())]

        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert FailureDetail.SEQUENCE_GAP in s.failure_detail
        assert s.failure_sequence == 1

    def test_causal_hash_mismatch(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=2)
        d1 = chain[1].to_dict()
        d1["causal_hash"] = "c" * 64

        env1 = ExecutionEnvelope.from_dict(d1)
        env1.signature = key.sign(env1.canonical_bytes_for_signing())

        lines = [json.dumps(chain[0].to_dict()), json.dumps(env1.to_dict())]
        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert FailureDetail.CAUSAL_HASH_MISMATCH in s.failure_detail

    def test_duplicate_nonce(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3)
        d1 = chain[1].to_dict()
        d1["nonce"] = chain[0].nonce

        env1 = ExecutionEnvelope.from_dict(d1)
        env1.signature = key.sign(env1.canonical_bytes_for_signing())

        lines = [json.dumps(chain[0].to_dict()), json.dumps(env1.to_dict())]
        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert FailureDetail.DUPLICATE_NONCE in s.failure_detail

    def test_chain_break_recovery_boundary(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=6)
        lines = [json.dumps(e.to_dict()) for e in chain[:5]]

        d5 = chain[5].to_dict()
        d5["causal_hash"] = "d" * 64
        env5 = ExecutionEnvelope.from_dict(d5)
        env5.signature = key.sign(env5.canonical_bytes_for_signing())
        lines.append(json.dumps(env5.to_dict()))

        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = recovery(p)
        assert s.verified_count == 5
        assert s.failure_sequence == 5
        assert s.integrity_boundary_hash == compute_boundary_hash(chain[4])
        assert s.boundary_sequence == 4


# ── FILE-TRUTH: failure_sequence = line_num always ───────────────────────────

class TestFailureSequenceIsLineNum:

    def test_failure_at_line_2(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=2)
        lines = [
            json.dumps(chain[0].to_dict()),
            json.dumps(chain[1].to_dict()),
            "{BROKEN}",
        ]

        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = strict(p)
        assert s.failure_sequence == 2

    def test_recovery_failure_at_line_10(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=10)
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BROKEN}"]

        p = tmp_path / "bad.jsonl"
        _write_lines(p, lines)

        s = recovery(p)
        assert s.failure_sequence == 10
        assert s.verified_count == 10


# ── Boundary hash reproducibility ────────────────────────────────────────────

class TestBoundaryHashReproducibility:

    def test_deterministic(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5)
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BAD}"]

        p = tmp_path / "det.jsonl"
        _write_lines(p, lines)

        s1 = recovery(p)
        s2 = recovery(p)
        assert s1.integrity_boundary_hash == s2.integrity_boundary_hash

    def test_formula(self):
        key = _make_key()
        chain = _make_chain(key, count=3)
        last = chain[-1]

        expected = hashlib.sha256(
            canonical_json_encode(last.to_signing_dict())
        ).hexdigest()

        assert compute_boundary_hash(last) == expected
        assert len(expected) == 64


# ── Cold verification ─────────────────────────────────────────────────────────

class TestColdVerification:

    def test_cold_verify_full(self, tmp_path):
        path = tmp_path / "cold.jsonl"
        key = _make_key()
        chain = _make_chain(key, count=10)
        _write_jsonl(path, chain)
        del chain, key

        s = strict(path)
        assert s.chain_valid
        assert s.total_entries == 10

    def test_cold_verify_recovery_partial(self, tmp_path):
        path = tmp_path / "cold_partial.jsonl"
        key = _make_key()
        chain = _make_chain(key, count=5)
        expected_boundary = compute_boundary_hash(chain[4])
        lines = [json.dumps(e.to_dict()) for e in chain] + ["{BROKEN}"]
        _write_lines(path, lines)
        del chain, key

        s = recovery(path)
        assert s.verified_count == 5
        assert s.integrity_boundary_hash == expected_boundary

    def test_raw_stdlib_round_trip(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=8)
        path = tmp_path / "raw.jsonl"

        with open(path, "w", encoding="utf-8") as f:
            for env in chain:
                f.write(json.dumps(env.to_dict()) + "\n")

        del chain, key

        s = strict(path)
        assert s.chain_valid
        assert s.total_entries == 8


# ── Valid ledger baseline ─────────────────────────────────────────────────────

class TestValidLedger:

    def test_valid_strict(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=20)
        path = tmp_path / "valid.jsonl"
        _write_jsonl(path, chain)

        s = strict(path)
        assert s.chain_valid
        assert s.total_entries == 20
        assert s.failure_type is None
        assert s.failure_sequence is None

    def test_valid_recovery_full(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=20)
        path = tmp_path / "valid.jsonl"
        _write_jsonl(path, chain)

        s = recovery(path)
        assert s.chain_valid
        assert s.total_entries == 20
        assert s.recovery_mode_active
        assert not s.partial_integrity
        assert s.integrity_boundary_hash is None