"""
guardclaw/core/replay.py
GEF Replay Engine — HARDENED v1.1.2

Replay is strictly key-agnostic and encryption-agnostic.
Encrypted envelopes are verified as opaque signed records only.
This module imports no symmetric key material, no cipher modules,
and performs no payload decoding of any kind.

Verification order per record (strict and recovery modes):
    1.  Size guard (1 MB limit)
    2.  JSON decode
    3.  Unknown fields check (strict only)
    4.  gef_version fast-fail
    5.  Envelope parse
    6.  Signature presence
    7.  Signature encoding + Ed25519 verification
    8.  Full schema check
    9.  Genesis position rule
    10. Signer + session consistency
    11. Interrupted terminal rule
    12. Sequence continuity
    13. Record ID uniqueness
    14. Causal hash chain
    15. Nonce uniqueness
    16. Identity enforcement (Phase 2, optional registry)
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import List, Optional, Set

from guardclaw.core.failure import (
    FailureDetail, FailureType, VerificationSummary,
    compute_boundary_hash, first_schema_error
)
from guardclaw.core.models import (
    ExecutionEnvelope, GENESIS_HASH, GEF_VERSION, RecordType, check_unknown_fields
)


def validate_identity(env: ExecutionEnvelope, registry) -> Optional[tuple]:
    """
    Validate identity binding for an envelope.

    Rules:
        key_id is None  -> skip (backward compat with v1.0 ledgers)
        key_id present  -> enforce registry: exists, not revoked, key matches

    Returns:
        None                         if valid or key_id absent
        (FailureType, FailureDetail) if invalid
    """
    if env.key_id is None:
        return None

    from guardclaw.core.registry import (
        KeyNotFoundError, KeyRevokedError, KeyMismatchError
    )

    try:
        registry.verify_binding(env.key_id, env.signer_public_key)
    except KeyNotFoundError:
        return (FailureType.IDENTITY_VIOLATION, FailureDetail.UNKNOWN_KEY_ID)
    except KeyRevokedError:
        return (FailureType.IDENTITY_VIOLATION, FailureDetail.REVOKED_KEY)
    except KeyMismatchError:
        return (FailureType.IDENTITY_VIOLATION, FailureDetail.KEY_ID_MISMATCH)

    return None


class ReplayEngine:
    def __init__(
        self,
        mode: str = "strict",
        silent: bool = False,
        registry=None,
    ):
        if mode not in ("strict", "recovery"):
            raise ValueError("invalid mode")
        self.mode = mode
        self._silent = silent
        self._registry = registry
        self.envelopes: List[ExecutionEnvelope] = []

    def stream_verify(self, ledger_path: Path) -> VerificationSummary:
        lp = Path(ledger_path)
        is_rec = self.mode == "recovery"
        if not lp.exists():
            return VerificationSummary(
                0, False,
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.FILE_NOT_FOUND,
                recovery_mode_active=is_rec,
            )
        return (
            self._stream_verify_strict(lp)
            if self.mode == "strict"
            else self._stream_verify_recovery(lp)
        )

    def load(self, path: Path) -> None:
        """
        Load envelopes from ledger file into self.envelopes.

        On any parse failure: stops loading, records structured error,
        sets self._load_error. Does NOT silently swallow exceptions.
        """
        self.envelopes = []
        self._load_error: Optional[str] = None
        line_num = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f):
                    if not line.strip():
                        continue
                    try:
                        env = ExecutionEnvelope.from_dict(json.loads(line))
                        self.envelopes.append(env)
                    except json.JSONDecodeError as exc:
                        self._load_error = (
                            f"json_decode_error:line_{line_num}:{exc}"
                        )
                        break
                    except (TypeError, KeyError, ValueError) as exc:
                        self._load_error = (
                            f"envelope_parse_error:line_{line_num}:"
                            f"{type(exc).__name__}:{exc}"
                        )
                        break
        except OSError as exc:
            self._load_error = f"file_read_error:{type(exc).__name__}:{exc}"

    # ─────────────────────────────────────────────────────────────────────────
    # STRICT MODE
    # ─────────────────────────────────────────────────────────────────────────

    def _stream_verify_strict(self, path: Path) -> VerificationSummary:
        prev: Optional[ExecutionEnvelope] = None
        first_sig: Optional[str] = None
        first_sess: Optional[str] = None
        seen_nonces: Set[str] = set()
        seen_ids: Set[str] = set()
        verified, count, expected_seq = 0, 0, 0
        is_int = False
        identity_checked = False

        def _fail(line_num, ftype, fdetail):
            return VerificationSummary(
                count, False,
                failure_sequence=line_num,
                failure_type=ftype,
                failure_detail=fdetail,
                verified_count=verified,
                identity_enforced=identity_checked,
            )

        with open(path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f):
                if not raw.strip():
                    continue
                count += 1

                # ── Step 0: Size guard ────────────────────────────────────
                if len(raw) > 1_048_576:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, FailureDetail.RECORD_TOO_LARGE)

                # ── Step 1: JSON decode ───────────────────────────────────
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    return _fail(line_num, FailureType.MALFORMED_JSON, FailureDetail.JSON_DECODE_ERROR)

                if not isinstance(data, dict):
                    return _fail(line_num, FailureType.MALFORMED_JSON, FailureDetail.JSON_DECODE_ERROR)

                # ── Step 1b: Unknown fields (strict only) ─────────────────
                unknowns = check_unknown_fields(data)
                if unknowns:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, "unknown_fields")

                # ── Step 1c: gef_version fast-fail ────────────────────────
                if data.get("gef_version") != GEF_VERSION:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, "invalid_gef_version")

                # ── Step 2: Parse envelope ────────────────────────────────
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except (TypeError, KeyError, ValueError) as e:
                    field_name = str(e).strip("'\"")
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, f"missing_field_{field_name}")

                # ── Step 3+4+5: Signature presence, encoding, crypto ──────
                raw_sig = data.get("signature", "")
                if not raw_sig:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, FailureDetail.MISSING_SIGNATURE)

                sig_ok, reason = env.verify_signature()
                if not sig_ok:
                    ft = FailureType.SIGNATURE_ENCODING_INVALID if reason == "encoding" else FailureType.SIGNATURE_INVALID
                    fd = FailureDetail.INVALID_BASE64URL if reason == "encoding" else FailureDetail.ED25519_FAILED
                    return _fail(line_num, ft, fd)

                # ── Step 6: Full schema — non-raising, collect errors ─────
                schema = env.collect_schema_errors()
                if not schema.valid:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, first_schema_error(schema.errors))

                # ── Step 7: Genesis position ──────────────────────────────
                if verified == 0:
                    if env.record_type != RecordType.GENESIS:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.GENESIS_MISSING)
                    if env.causal_hash != GENESIS_HASH:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.CAUSAL_HASH_MISMATCH)

                if env.record_type == RecordType.GENESIS and verified > 0:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.DUPLICATE_GENESIS)

                # ── Step 8: Signer + session consistency ──────────────────
                if not first_sig:
                    first_sig = env.signer_public_key
                    first_sess = env.session_id
                else:
                    if env.signer_public_key != first_sig:
                        return _fail(line_num, FailureType.SIGNER_MISMATCH, FailureDetail.SIGNER_MISMATCH)
                    if env.session_id != first_sess:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.SESSION_ID_MISMATCH)

                # ── Step 9: Interrupted terminal rule ─────────────────────
                if is_int:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.POST_INTERRUPTED_RECORD)

                # ── Step 10: Sequence continuity ──────────────────────────
                if env.sequence != expected_seq:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.SEQUENCE_GAP)

                # ── Step 11: Record ID uniqueness ─────────────────────────
                if env.record_id in seen_ids:
                    return _fail(line_num, FailureType.DUPLICATE_RECORD_ID, env.record_id)
                seen_ids.add(env.record_id)

                # ── Step 12: Causal hash chain ────────────────────────────
                if not env.verify_chain(prev):
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.CAUSAL_HASH_MISMATCH)

                # ── Step 13: Nonce uniqueness ─────────────────────────────
                if env.nonce in seen_nonces:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.DUPLICATE_NONCE)
                seen_nonces.add(env.nonce)

                # ── Step 14: Identity enforcement (Phase 2) ───────────────
                if self._registry is not None and env.key_id is not None:
                    identity_checked = True
                    id_fail = validate_identity(env, self._registry)
                    if id_fail:
                        return _fail(line_num, id_fail[0], id_fail[1])

                if env.record_type == RecordType.INTERRUPTED:
                    is_int = True
                prev = env
                verified += 1
                expected_seq += 1

        if count == 0:
            return VerificationSummary(
                0, False,
                verification_level="EMPTY",
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.EMPTY_LEDGER,
            )

        return VerificationSummary(
            count, True,
            interrupted=is_int,
            verified_count=verified,
            identity_enforced=identity_checked,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # RECOVERY MODE
    # ─────────────────────────────────────────────────────────────────────────

    def _stream_verify_recovery(self, path: Path) -> VerificationSummary:
        prev: Optional[ExecutionEnvelope] = None
        last_valid: Optional[ExecutionEnvelope] = None
        first_sig: Optional[str] = None
        first_sess: Optional[str] = None
        seen_nonces: Set[str] = set()
        seen_ids: Set[str] = set()
        verified, count, expected_seq = 0, 0, 0
        is_int = False
        identity_checked = False

        def _fail(line_num, ftype, fdetail):
            bh = compute_boundary_hash(last_valid) if last_valid else None
            return VerificationSummary(
                total_entries=count,
                chain_valid=False,
                recovery_mode_active=True,
                verified_count=verified,
                valid_signatures=verified,
                invalid_signatures=1,
                failure_sequence=line_num,
                failure_type=ftype,
                failure_detail=fdetail,
                integrity_boundary_hash=bh,
                boundary_sequence=last_valid.sequence if last_valid else None,
                identity_enforced=identity_checked,
            )

        with open(path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f):
                if not raw.strip():
                    continue
                count += 1

                if len(raw) > 1_048_576:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, FailureDetail.RECORD_TOO_LARGE)

                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    return _fail(line_num, FailureType.MALFORMED_JSON, FailureDetail.JSON_DECODE_ERROR)

                if not isinstance(data, dict):
                    return _fail(line_num, FailureType.MALFORMED_JSON, FailureDetail.JSON_DECODE_ERROR)

                if data.get("gef_version") != GEF_VERSION:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, "invalid_gef_version")

                try:
                    env = ExecutionEnvelope.from_dict(data)
                except (TypeError, KeyError, ValueError) as e:
                    field_name = str(e).strip("'\"")
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, f"missing_field_{field_name}")

                raw_sig = data.get("signature", "")
                if not raw_sig:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, FailureDetail.MISSING_SIGNATURE)

                sig_ok, reason = env.verify_signature()
                if not sig_ok:
                    ft = FailureType.SIGNATURE_ENCODING_INVALID if reason == "encoding" else FailureType.SIGNATURE_INVALID
                    fd = FailureDetail.INVALID_BASE64URL if reason == "encoding" else FailureDetail.ED25519_FAILED
                    return _fail(line_num, ft, fd)

                # ── Step 6: Full schema — non-raising, collect errors ─────
                schema = env.collect_schema_errors()
                if not schema.valid:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION, first_schema_error(schema.errors))

                if verified == 0:
                    if env.record_type != RecordType.GENESIS:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.GENESIS_MISSING)
                    if env.causal_hash != GENESIS_HASH:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.CAUSAL_HASH_MISMATCH)

                if env.record_type == RecordType.GENESIS and verified > 0:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.DUPLICATE_GENESIS)

                if not first_sig:
                    first_sig = env.signer_public_key
                    first_sess = env.session_id
                else:
                    if env.signer_public_key != first_sig:
                        return _fail(line_num, FailureType.SIGNER_MISMATCH, FailureDetail.SIGNER_MISMATCH)
                    if env.session_id != first_sess:
                        return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.SESSION_ID_MISMATCH)

                if is_int:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.POST_INTERRUPTED_RECORD)

                if env.sequence != expected_seq:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.SEQUENCE_GAP)

                if env.record_id in seen_ids:
                    return _fail(line_num, FailureType.DUPLICATE_RECORD_ID, env.record_id)
                seen_ids.add(env.record_id)

                if not env.verify_chain(prev):
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.CAUSAL_HASH_MISMATCH)

                if env.nonce in seen_nonces:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION, FailureDetail.DUPLICATE_NONCE)
                seen_nonces.add(env.nonce)

                # Identity checked BEFORE last_valid is updated
                if self._registry is not None and env.key_id is not None:
                    identity_checked = True
                    id_fail = validate_identity(env, self._registry)
                    if id_fail:
                        return _fail(line_num, id_fail[0], id_fail[1])

                # last_valid set AFTER all checks pass
                if env.record_type == RecordType.INTERRUPTED:
                    is_int = True
                last_valid = env
                prev = env
                verified += 1
                expected_seq += 1

        if count == 0:
            return VerificationSummary(
                0, False,
                verification_level="EMPTY",
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.EMPTY_LEDGER,
                recovery_mode_active=True,
            )

        return VerificationSummary(
            count, True,
            interrupted=is_int,
            recovery_mode_active=True,
            verified_count=verified,
            identity_enforced=identity_checked,
        )