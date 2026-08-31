"""
tests/test_phase1_backward_compat.py

Phase 1 Backward Compatibility Gate
Run after EVERY Phase 1 step. Must always be 4/4.
"""
from __future__ import annotations
import json
from pathlib import Path

import pytest

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import RecordType
from guardclaw.core.replay import ReplayEngine

CANONICAL_V1_FIELDS = {
    "gef_version", "record_id", "record_type", "agent_id",
    "session_id", "sequence", "timestamp", "causal_hash",
    "nonce", "payload", "signer_public_key", "signature",
}


def _make_ledger(tmp_path, n=0):
    key = Ed25519KeyManager.generate()
    ledger = GEFLedger(key_manager=key, agent_id="test", ledger_path=str(tmp_path))
    for i in range(n):
        ledger.emit(RecordType.EXECUTION, {"i": i})
    return key, ledger


def _ledger_path(tmp_path):
    return str(tmp_path / "ledger.jsonl")


def _load_lines(path):
    return Path(path).read_text(encoding="utf-8").splitlines()


class TestPhase1BackwardCompat:

    def test_v1_ledger_verifies_under_phase1_verifier(self, tmp_path):
        """A v1.0 ledger with zero Phase 1 fields must verify identically."""
        _make_ledger(tmp_path, n=5)
        s = ReplayEngine(mode="strict", silent=True).stream_verify(
            Path(_ledger_path(tmp_path))
        )
        assert s.chain_valid is True
        assert s.total_entries == 6

    def test_phase1_fields_absent_means_omitted_not_null(self, tmp_path):
        """No Phase 1 field should appear as null in a v1.0 envelope."""
        _make_ledger(tmp_path, n=1)
        lines = _load_lines(_ledger_path(tmp_path))
        for line in lines:
            d = json.loads(line)
            assert "key_id" not in d
            assert "trusted_timestamp" not in d

    def test_v1_0_ledger_has_exactly_12_canonical_fields(self, tmp_path):
        """Raw JSONL of a v1.0 ledger must contain exactly the 12 canonical fields."""
        _make_ledger(tmp_path, n=1)
        lines = _load_lines(_ledger_path(tmp_path))
        for line in lines:
            d = json.loads(line)
            assert set(d.keys()) == CANONICAL_V1_FIELDS, (
                f"Unexpected fields: {set(d.keys()) - CANONICAL_V1_FIELDS}"
            )

    def test_signing_surface_excludes_signature_only(self, tmp_path):
        """Signing surface must be to_dict() minus signature — no other filtering."""
        from guardclaw.core.models import ExecutionEnvelope
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="test", ledger_path=str(tmp_path))
        ledger.emit(RecordType.EXECUTION, {"x": 1})
        lines = _load_lines(_ledger_path(tmp_path))
        d = json.loads(lines[1])
        env = ExecutionEnvelope.from_dict(d)
        surface = env.canonical_signing_surface()
        # signature must not be in surface
        assert "signature" not in surface
        # all other present fields must be in surface
        for k in d:
            if k != "signature":
                assert k in surface, f"Field {k!r} missing from signing surface"