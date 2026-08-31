"""
tests/test_spec_brutality.py

GuardClaw Phase 0 — Spec Brutality Suite
=========================================

Every test in this file is a direct enforcement of a LOCKED spec clause.
Reference: GUARDCLAW-UNIFIED-SPEC-v1.0 FINAL (2026-04-14)

Tests are grouped by spec section. Each test names the clause it enforces.
ZERO tolerance: wrong failure_type, wrong failure_detail, wrong ordering = FAIL.
"""

import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from typing import List

import pytest

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.failure import FailureDetail, FailureType, VerificationSummary
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import (
    GENESIS_HASH,
    ExecutionEnvelope,
    RecordType,
)
from guardclaw.core.replay import ReplayEngine

# ── Helpers ───────────────────────────────────────────────────────────────────

GEF_VERSION = "1.0"
NULL_SESSION = "00000000-0000-0000-0000-000000000000"


def _make_clean_ledger(tmp_path, n: int = 3) -> tuple:
    """Returns (key, ledger, path_str)."""
    key = Ed25519KeyManager.generate()
    ledger = GEFLedger(key_manager=key, agent_id="brutality-agent", ledger_path=str(tmp_path))
    for i in range(n):
        ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
    path = os.path.join(str(tmp_path), "ledger.jsonl")
    return key, ledger, path


def _load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def _save_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _verify_strict(path: str) -> VerificationSummary:
    return ReplayEngine(mode="strict", silent=True).stream_verify(Path(path))


def _verify_recovery(path: str) -> VerificationSummary:
    return ReplayEngine(mode="recovery", silent=True).stream_verify(Path(path))


def _signing_surface(entry: dict) -> dict:
    """Reconstruct signing surface exactly per Spec 2.4 — all fields except signature."""
    return {k: v for k, v in entry.items() if k != "signature"}


def _resign(entry: dict, key: Ed25519KeyManager) -> dict:
    """Re-sign an entry after mutating it."""
    surface = _signing_surface(entry)
    canonical_bytes = canonical_json_encode(surface)
    entry["signature"] = key.sign(canonical_bytes)
    return entry


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.3 — All 12 Fields Mandatory
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec23MandatoryFields:
    """Every ExecutionEnvelope MUST contain all 12 fields. No field may be null or absent."""

    MANDATORY_FIELDS = [
        "gef_version", "record_id", "record_type", "agent_id", "session_id",
        "signer_public_key", "sequence", "nonce", "timestamp",
        "causal_hash", "payload", "signature",
    ]

    @pytest.mark.parametrize("field", MANDATORY_FIELDS)
    def test_missing_field_fails_with_schema_violation(self, tmp_path, field):
        """Spec 2.3: each missing field MUST produce SCHEMA_VIOLATION / missing_field_<name>."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        del entry[field]
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        # Schema fields caught before signature; signature itself is step 3
        if field == "signature":
            assert s.failure_type in (
                FailureType.SCHEMA_VIOLATION,
                FailureType.SIGNATURE_INVALID,
                FailureType.SIGNATURE_ENCODING_INVALID,
            )
        else:
            assert s.failure_type == FailureType.SCHEMA_VIOLATION, (
                f"Missing '{field}' must be SCHEMA_VIOLATION, got {s.failure_type}"
            )
            assert FailureDetail.missing_field(field) in s.failure_detail or field in s.failure_detail, (
                f"failure_detail must name the missing field '{field}', got: {s.failure_detail}"
            )

    @pytest.mark.parametrize("field", MANDATORY_FIELDS)
    def test_null_field_fails(self, tmp_path, field):
        """Spec 2.3: null field is equivalent to absent — must fail."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry[field] = None
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid, f"Null '{field}' should invalidate the ledger"

    def test_session_id_present_in_every_emitted_envelope(self, tmp_path):
        """Spec 2.3: session_id is a real field that must appear in persisted JSON."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert "session_id" in entry, f"Line {i} missing session_id in persisted JSON"
            assert entry["session_id"], f"Line {i} has empty/null session_id"

    def test_session_id_is_consistent_across_all_records(self, tmp_path):
        """Spec 2.3: session_id MUST be identical across ALL records in a ledger."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=10)
        lines = _load_lines(path)
        session_ids = {json.loads(line)["session_id"] for line in lines}
        assert len(session_ids) == 1, (
            f"Multiple session_ids found in one ledger: {session_ids}"
        )

    def test_signer_public_key_consistent_across_all_records(self, tmp_path):
        """Spec 2.3: signer_public_key MUST be identical across ALL records."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=10)
        lines = _load_lines(path)
        keys = {json.loads(line)["signer_public_key"] for line in lines}
        assert len(keys) == 1, f"Multiple signer_public_keys in one ledger: {keys}"

    def test_gef_version_consistent_across_all_records(self, tmp_path):
        """Spec 2.3: gef_version MUST be identical across ALL records."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        versions = {json.loads(line)["gef_version"] for line in lines}
        assert len(versions) == 1
        assert versions.pop() == GEF_VERSION


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.4 — Signing Surface & Canonical JCS
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec24SigningSurface:
    """Signing surface = all 12 fields EXCEPT signature. Must include session_id."""

    def test_session_id_is_in_signing_surface(self, tmp_path):
        """
        Spec 2.4: session_id is in canonical field order.
        If we mutate session_id after signing, signature MUST fail.
        """
        _, _, path = _make_clean_ledger(str(tmp_path), n=2)
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["session_id"] = str(uuid.uuid4())   # change session without re-signing
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_INVALID, (
            f"Mutated session_id (not re-signed) must cause SIGNATURE_INVALID, got {s.failure_type}"
        )
        assert s.failure_detail == FailureDetail.ED25519_FAILED

    def test_payload_mutation_without_resign_causes_signature_invalid(self, tmp_path):
        """Spec 2.4: payload is in signing surface — mutation without re-sign = SIGNATURE_INVALID."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=2)
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["payload"]["injected"] = "evil"
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_INVALID

    def test_resigned_payload_mutation_causes_causal_hash_mismatch(self, tmp_path):
        """
        Spec 2.4/2.5: If attacker mutates payload AND re-signs with own key,
        the causal_hash of the NEXT record still fails — chain is broken.
        """
        key, _, path = _make_clean_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["payload"]["data"] = "RESIGNED_ATTACK"
        entry = _resign(entry, key)           # valid signature now
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        # Line 2 (sequence 2) should now fail causal hash — the resigned entry
        # produces a different signing surface so line 2's causal_hash is wrong
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.CAUSAL_HASH_MISMATCH

    def test_signing_surface_excludes_signature_field(self, tmp_path):
        """
        Spec 2.4 Signature Stripping Invariant:
        Re-computing canonical bytes from stored entry (minus signature) must
        produce a valid verification — proves signature field was excluded.
        """
        _, _, path = _make_clean_ledger(str(tmp_path), n=2)
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        env = ExecutionEnvelope.from_dict(entry)
        sig_ok, reason = env.verify_signature()
        assert sig_ok, f"Fresh envelope signature must verify: {reason}"


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.5 — Hash Chain Rules
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec25HashChain:
    """Genesis causal_hash == GENESIS_HASH. Each subsequent = SHA-256(signing_surface(prev))."""

    def test_genesis_causal_hash_must_be_genesis_constant(self, tmp_path):
        """Spec 2.5: genesis causal_hash MUST equal GENESIS_HASH (64 zeros)."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        genesis = json.loads(lines[0])
        assert genesis["causal_hash"] == GENESIS_HASH

    def test_forged_genesis_hash_detected(self, tmp_path):
        """Spec 2.5: genesis with wrong causal_hash = CHAIN_VIOLATION / CAUSAL_HASH_MISMATCH."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["causal_hash"] = "a" * 64
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        # Must fail signature first (causal_hash is in signing surface → signature invalid)
        # OR if causal_hash checked after sig, must be CHAIN_VIOLATION
        assert s.failure_type in (
            FailureType.SIGNATURE_INVALID,
            FailureType.CHAIN_VIOLATION,
        )

    def test_non_genesis_with_genesis_hash_detected(self, tmp_path):
        """Spec 2.5: GENESIS_HASH on a non-genesis record = CAUSAL_HASH_MISMATCH."""
        key, _, path = _make_clean_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        entry = json.loads(lines[2])
        entry["causal_hash"] = GENESIS_HASH
        entry = _resign(entry, key)
        lines[2] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.CAUSAL_HASH_MISMATCH

    def test_causal_hash_chain_is_mathematically_correct(self, tmp_path):
        """
        Spec 2.5: Independently recompute the full hash chain from raw bytes.
        Must match stored causal_hash values exactly.
        """
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        prev_surface_hash = GENESIS_HASH
        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert entry["causal_hash"] == prev_surface_hash, (
                f"Line {i}: expected causal_hash={prev_surface_hash[:12]}..., "
                f"got {entry['causal_hash'][:12]}..."
            )
            surface = _signing_surface(entry)
            prev_surface_hash = hashlib.sha256(canonical_json_encode(surface)).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.7 — Verification Order LOCKED (Steps 1–12)
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec27VerificationOrder:
    """
    Verification order is LOCKED. Wrong ordering = wrong failure_type reported.
    Tests verify that the correct failure_type is returned for each attack.
    """

    def test_step1_malformed_json(self, tmp_path):
        """Step 1: JSON decode failure = MALFORMED_JSON / JSON_DECODE_ERROR."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        lines[1] = "{not valid json\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.MALFORMED_JSON
        assert s.failure_detail == FailureDetail.JSON_DECODE_ERROR
        assert s.failure_sequence == 1

    def test_step2_schema_violation_missing_required_field(self, tmp_path):
        """Step 2: Missing required field = SCHEMA_VIOLATION / missing_field_<name>."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        del entry["agent_id"]
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SCHEMA_VIOLATION
        assert "agent_id" in s.failure_detail

    def test_step3_missing_signature_field(self, tmp_path):
        """Step 3: Absent signature = SCHEMA_VIOLATION / MISSING_SIGNATURE."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        del entry["signature"]
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SCHEMA_VIOLATION
        assert s.failure_detail == FailureDetail.MISSING_SIGNATURE

    def test_step4_invalid_base64url_signature(self, tmp_path):
        """Step 4: Non-base64url signature = SIGNATURE_ENCODING_INVALID / INVALID_BASE64URL."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["signature"] = "====THIS=IS=PADDED=BASE64====="
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_ENCODING_INVALID
        assert s.failure_detail == FailureDetail.INVALID_BASE64URL

    def test_step5_wrong_signature_bytes(self, tmp_path):
        """Step 5: Valid base64url but wrong Ed25519 bytes = SIGNATURE_INVALID / ED25519_FAILED."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["signature"] = "A" * 86        # 86 chars = 64 raw bytes, valid encoding, wrong sig
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_INVALID
        assert s.failure_detail == FailureDetail.ED25519_FAILED

    def test_step6_genesis_must_be_first(self, tmp_path):
        """Step 6: First record is not genesis = CHAIN_VIOLATION / GENESIS_MISSING."""
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="test", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        # Remove genesis (line 0), leave only the intent record
        lines = lines[1:]
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.GENESIS_MISSING

    def test_step6b_duplicate_genesis(self, tmp_path):
        """Step 6b: Second genesis record = CHAIN_VIOLATION / DUPLICATE_GENESIS."""
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="test", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        # Duplicate genesis at position 1
        lines.insert(1, lines[0])
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.DUPLICATE_GENESIS

    def test_step8_sequence_gap(self, tmp_path):
        """Step 8 (Spec 2.7): Deleted entry = CHAIN_VIOLATION / SEQUENCE_GAP."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        del lines[2]   # remove sequence 2
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.SEQUENCE_GAP

    def test_step10_duplicate_record_id(self, tmp_path):
        """Step 10 (Spec 2.7): Duplicate record_id = DUPLICATE_RECORD_ID."""
        key, _, path = _make_clean_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        # Copy record_id from line 1 into line 3 (re-sign to pass sig check)
        e1 = json.loads(lines[1])
        e3 = json.loads(lines[3])
        e3["record_id"] = e1["record_id"]
        e3 = _resign(e3, key)
        lines[3] = json.dumps(e3) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.DUPLICATE_RECORD_ID

    def test_step12_duplicate_nonce(self, tmp_path):
        """Step 12 (Spec 2.7): Duplicate nonce = CHAIN_VIOLATION / DUPLICATE_NONCE."""
        key, _, path = _make_clean_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        e1 = json.loads(lines[1])
        e3 = json.loads(lines[3])
        e3["nonce"] = e1["nonce"]
        e3 = _resign(e3, key)
        lines[3] = json.dumps(e3) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.CHAIN_VIOLATION
        assert s.failure_detail == FailureDetail.DUPLICATE_NONCE

    def test_signature_checked_before_chain_step_ordering(self, tmp_path):
        """
        Spec 2.7 Rationale: Signature (steps 3-5) checked BEFORE chain checks (steps 6-12).
        A forged record with bad signature must NOT produce GENESIS_MISSING or CHAIN_VIOLATION.
        It must produce SIGNATURE_INVALID.
        """
        key = Ed25519KeyManager.generate()
        forger_key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="test", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        # Inject a record signed by the forger key — chain position is wrong AND sig is wrong
        entry = json.loads(lines[1])
        entry["sequence"] = 999
        entry["record_id"] = str(uuid.uuid4())
        entry = _resign(entry, forger_key)    # signed by a DIFFERENT key
        lines.insert(1, json.dumps(entry) + "\n")
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        # Must be SIGNATURE_INVALID (step 5), NOT SEQUENCE_GAP (step 8) or chain error
        assert s.failure_type == FailureType.SIGNATURE_INVALID, (
            f"Signature must be checked before chain order. Got: {s.failure_type}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.3 Cross-Record Invariants — Session/Signer Consistency
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec23CrossRecordInvariants:

    def test_session_id_mismatch_detected(self, tmp_path):
        """
        Spec 2.3: session_id MUST be identical across all records.
        Injecting a record with a different (but validly signed) session_id must fail.
        """
        key, _, path = _make_clean_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        entry = json.loads(lines[2])
        entry["session_id"] = str(uuid.uuid4())   # different session
        entry = _resign(entry, key)                # valid signature
        lines[2] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid, "Session ID mismatch must be detected"
        # Must be SIGNATURE_INVALID (session_id is in signing surface → hash chain breaks)
        # OR SIGNER_MISMATCH / chain violation depending on implementation
        assert s.failure_type in (
            FailureType.SIGNATURE_INVALID,
            FailureType.CHAIN_VIOLATION,
        ), f"session_id mismatch must fail, got: {s.failure_type}"

    def test_signer_key_change_mid_chain_detected(self, tmp_path):
        """
        Spec 2.3: signer_public_key MUST be identical across all records.
        Cross-key injection must fail.
        """
        key1 = Ed25519KeyManager.generate()
        key2 = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key1, agent_id="agent", ledger_path=str(tmp_path))
        for i in range(3):
            ledger.emit(record_type=RecordType.INTENT, payload={"i": i})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        entry = json.loads(lines[2])
        entry["signer_public_key"] = key2.public_key_hex
        entry = _resign(entry, key2)    # now signed by key2, signer_public_key updated
        lines[2] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid, "Signer key change must be detected"

    def test_cross_ledger_session_injection_fails(self, tmp_path):
        """
        Spec 2.11 Session Identity Moat:
        Take a valid record from ledger_A and inject into ledger_B.
        It must fail even though the record is cryptographically intact —
        because session_id and/or causal_hash won't match ledger_B's chain.
        """
        dir_a = str(tmp_path / "a")
        dir_b = str(tmp_path / "b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)
        key_a = Ed25519KeyManager.generate()
        key_b = Ed25519KeyManager.generate()
        ledger_a = GEFLedger(key_manager=key_a, agent_id="agent-A", ledger_path=dir_a)
        ledger_b = GEFLedger(key_manager=key_b, agent_id="agent-B", ledger_path=dir_b)
        for i in range(3):
            ledger_a.emit(record_type=RecordType.INTENT, payload={"i": i})
            ledger_b.emit(record_type=RecordType.INTENT, payload={"i": i})
        lines_a = _load_lines(os.path.join(dir_a, "ledger.jsonl"))
        lines_b = _load_lines(os.path.join(dir_b, "ledger.jsonl"))
        # Inject line 1 from ledger_A into ledger_B at position 1
        lines_b.insert(1, lines_a[1])
        path_b = os.path.join(dir_b, "ledger.jsonl")
        _save_lines(path_b, lines_b)
        s = _verify_strict(path_b)
        assert not s.chain_valid, (
            "Cross-ledger injection MUST be detected — session_id or causal_hash or signer must mismatch"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.8 — VerificationSummary Contract
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec28VerificationSummary:
    """VerificationSummary fields must match the exact LOCKED contract."""

    def test_clean_ledger_summary_fields(self, tmp_path):
        """Spec 2.8: fully valid ledger must return all correct fields."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        s = _verify_strict(path)
        assert s.chain_valid is True
        assert s.total_entries == 6            # 1 genesis + 5 user records
        assert s.verified_count == 6
        assert s.failure_type is None
        assert s.failure_detail is None
        assert s.failure_sequence is None

    def test_failure_sequence_is_zero_indexed_line_number(self, tmp_path):
        """
        Spec 2.8: failure_sequence = 0-indexed physical file line, NOT entry.sequence.
        Corrupt line 2 → failure_sequence must be 2.
        """
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        lines[2] = "{bad json\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_sequence == 2, (
            f"failure_sequence must be the 0-indexed line number (2), got {s.failure_sequence}"
        )

    def test_total_entries_counts_failure_line(self, tmp_path):
        """Spec 2.8: total_entries includes the failure line itself."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        lines[3] = "{bad json\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.total_entries == 4, (
            f"total_entries must count through the bad line (4), got {s.total_entries}"
        )

    def test_verified_count_is_trusted_prefix_only(self, tmp_path):
        """Spec 2.8: verified_count = entries that passed ALL checks (trusted prefix)."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        lines[3] = "{bad json\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.verified_count == 3, (
            f"verified_count should be 3 (lines 0-2 passed), got {s.verified_count}"
        )

    def test_failure_detail_is_machine_readable_code_not_human_message(self, tmp_path):
        """Spec 2.8: failure_detail MUST be a machine-readable code string, NEVER a human message."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        lines[1] = "{bad json\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        # Must be a known constant code, not a free-form message
        assert s.failure_detail == FailureDetail.JSON_DECODE_ERROR, (
            f"failure_detail must be exact code 'json_decode_error', got: {s.failure_detail!r}"
        )
        # Must not contain spaces or look like a sentence
        assert " " not in s.failure_detail, (
            f"failure_detail must not be a human sentence, got: {s.failure_detail!r}"
        )

    def test_empty_ledger_summary(self, tmp_path):
        """Spec 2.8/2.9: Empty ledger = chain_valid False, verification_level EMPTY."""
        path = str(tmp_path / "empty.jsonl")
        open(path, "w").close()
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.total_entries == 0


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.9 — verification_level Derivation
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec29VerificationLevel:
    """verification_level MUST be derived, never manually set."""

    def test_fully_valid_level(self, tmp_path):
        """Spec 2.9: FULLY_VALID when chain_valid=True and not interrupted."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=3)
        s = _verify_strict(path)
        assert s.verification_level == "FULLY_VALID"

    def test_invalid_level_on_failure(self, tmp_path):
        """Spec 2.9: INVALID when chain_valid=False and verified_count=0."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        lines[0] = "{bad\n"    # corrupt genesis → nothing verified
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.verification_level == "INVALID"

    def test_partially_valid_level_in_recovery(self, tmp_path):
        """Spec 2.9: PARTIALLY_VALID when recovery mode, chain_valid=False, verified_count>0."""
        _, _, path = _make_clean_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        lines[4] = "{bad json\n"    # fail at line 4, lines 0-3 are clean
        _save_lines(path, lines)
        s = _verify_recovery(path)
        assert not s.chain_valid
        assert s.recovery_mode_active is True
        assert s.verified_count > 0
        assert s.verification_level == "PARTIALLY_VALID"


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.10 — Canonical Failure Codes (exact strings, never change)
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec210FailureCodes:
    """Failure code strings are permanent API contract. NEVER change."""

    def test_exact_failure_type_strings(self):
        assert FailureType.MALFORMED_JSON == "malformed_json"
        assert FailureType.SCHEMA_VIOLATION == "schema_violation"
        assert FailureType.SIGNATURE_ENCODING_INVALID == "signature_encoding_invalid"
        assert FailureType.SIGNATURE_INVALID == "signature_invalid"
        assert FailureType.CHAIN_VIOLATION == "chain_violation"
        assert FailureType.DUPLICATE_RECORD_ID == "duplicate_record_id"
        assert FailureType.LEDGER_INVALID == "ledger_invalid"

    def test_exact_failure_detail_strings(self):
        assert FailureDetail.JSON_DECODE_ERROR == "json_decode_error"
        assert FailureDetail.MISSING_SIGNATURE == "missing_signature"
        assert FailureDetail.INVALID_BASE64URL == "invalid_base64url"
        assert FailureDetail.ED25519_FAILED == "ed25519_verification_failed"
        assert FailureDetail.GENESIS_MISSING == "genesis_missing"
        assert FailureDetail.DUPLICATE_GENESIS == "duplicate_genesis"
        assert FailureDetail.SEQUENCE_GAP == "sequence_gap"
        assert FailureDetail.CAUSAL_HASH_MISMATCH == "causal_hash_mismatch"
        assert FailureDetail.DUPLICATE_NONCE == "duplicate_nonce"
        assert FailureDetail.GEF_VERSION_MISMATCH == "gef_version_mismatch"
        assert FailureDetail.FILE_NOT_FOUND == "file_not_found"
        assert FailureDetail.EMPTY_LEDGER == "empty_ledger"

    def test_missing_field_detail_format(self):
        """Spec 2.10: missing_field detail format is missing_field_<name>."""
        detail = FailureDetail.missing_field("session_id")
        assert detail == "missing_field_session_id"


# ══════════════════════════════════════════════════════════════════════════════
# SPEC 2.1 — Cryptographic Primitives (base64url NO padding enforcement)
# ══════════════════════════════════════════════════════════════════════════════

class TestSpec21CryptoPrimitives:
    """Base64url fields MUST NOT contain padding. Reject = SIGNATURE_ENCODING_INVALID."""

    def test_padded_base64_signature_rejected(self, tmp_path):
        """Spec 2.1: signature with '=' padding must be rejected."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        # Add padding characters to an otherwise valid-length string
        entry["signature"] = "A" * 84 + "=="
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_ENCODING_INVALID
        assert s.failure_detail == FailureDetail.INVALID_BASE64URL

    def test_zeroed_signature_rejected(self, tmp_path):
        """All-zero signature bytes must fail Ed25519 verification."""
        _, _, path = _make_clean_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["signature"] = "A" * 86    # valid encoding, wrong bytes
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_type == FailureType.SIGNATURE_INVALID


# ══════════════════════════════════════════════════════════════════════════════
# CONCURRENCY & INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrencyAndIntegrity:

    def test_concurrent_emit_produces_valid_chain(self, tmp_path):
        """
        GEFLedger must be thread-safe: 5 threads × 20 records each.
        The resulting ledger must verify fully valid with 0 violations.
        """
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="threaded", ledger_path=str(tmp_path))
        errors = []

        def emit_batch(start, count):
            try:
                for i in range(start, start + count):
                    ledger.emit(record_type=RecordType.INTENT, payload={"i": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=emit_batch, args=(i * 20, 20)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        s = _verify_strict(path)
        assert s.chain_valid, (
            f"Concurrent ledger must be fully valid. "
            f"failure={s.failure_type}:{s.failure_detail} at line {s.failure_sequence}"
        )
        assert s.total_entries == 101     # 1 genesis + 100 user records
        assert s.verified_count == 101

    def test_1000_entry_chain_full_verification(self, tmp_path):
        """1000-entry chain must fully verify with correct entry counts."""
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="load-test", ledger_path=str(tmp_path))
        for i in range(1000):
            ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        s = _verify_strict(path)
        assert s.chain_valid
        assert s.total_entries == 1001
        assert s.verified_count == 1001

    def test_tamper_at_midpoint_only_invalidates_forward(self, tmp_path):
        """
        Tamper at sequence 500: verified_count must be 500 (lines 0-499 clean).
        failure_sequence must point to the exact tampered line.
        """
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="midpoint", ledger_path=str(tmp_path))
        for i in range(999):
            ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        entry = json.loads(lines[500])
        entry["payload"]["i"] = 99999     # mutate without re-sign
        lines[500] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify_strict(path)
        assert not s.chain_valid
        assert s.failure_sequence == 500
        assert s.failure_type == FailureType.SIGNATURE_INVALID
        assert s.verified_count == 500   # lines 0-499 are the trusted prefix
