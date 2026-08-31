import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.replay import ReplayEngine
from guardclaw.core.models import ExecutionEnvelope, RecordType
from guardclaw.core.failure import FailureType
from guardclaw.core.canonical import canonical_json_encode


ROOT = Path(__file__).resolve().parent
FAILURES = []


def fail(phase, severity, title, observed, expected, repro):
    FAILURES.append(
        {
            "phase": phase,
            "severity": severity,
            "title": title,
            "observed": observed,
            "expected": expected,
            "repro": repro,
        }
    )
    return "FAIL"


def pass_phase():
    return "PASS"


def strict(path):
    return ReplayEngine(mode="strict", parallel=False, silent=True).stream_verify(path)


def recovery(path):
    return ReplayEngine(mode="recovery", parallel=False, silent=True).stream_verify(path)


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            if isinstance(row, str):
                f.write(row)
                if not row.endswith("\n"):
                    f.write("\n")
            else:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def load_jsonl(path):
    return [json.loads(x) for x in load_lines(path) if x.strip()]


def make_ledger(count=3, agent_id="audit", start_record_type="genesis"):
    key = Ed25519KeyManager.generate()
    td = tempfile.TemporaryDirectory()
    ledger = GEFLedger(key_manager=key, agent_id=agent_id, ledger_path=td.name)
    ledger.emit(start_record_type, {"init": True} if start_record_type == "genesis" else {"step": 0})
    for i in range(1, count):
        ledger.emit("execution", {"step": i})
    path = os.path.join(td.name, "ledger.jsonl")
    return td, key, ledger, path


def phase_1_protocol_schema():
    td, key, ledger, path = make_ledger(count=2)
    try:
        rows = load_jsonl(path)
        valid = rows[1]

        required_fields = [
            "record_id",
            "sequence",
            "record_type",
            "agent_id",
            "timestamp",
            "payload",
            "causal_hash",
            "nonce",
            "gef_version",
            "signer_public_key",
            "signature",
        ]

        for field in required_fields:
            bad = dict(valid)
            bad.pop(field, None)
            p = os.path.join(td.name, f"missing_{field}.jsonl")
            write_jsonl(p, [rows[0], bad])
            s = strict(p)
            if s.chain_valid:
                return fail(
                    1, "CRITICAL", f"Missing field accepted: {field}",
                    f"chain_valid={s.chain_valid}, failure_type={s.failure_type}",
                    "schema_violation",
                    f"Remove field {field} from a valid envelope and run strict()",
                )
            if s.failure_type != FailureType.SCHEMA_VIOLATION:
                return fail(
                    1, "HIGH", f"Wrong classification for missing field: {field}",
                    f"failure_type={s.failure_type}, detail={s.failure_detail}",
                    "SCHEMA_VIOLATION with missing_field detail",
                    f"Remove field {field} and run strict()",
                )
            if not s.failure_detail:
                return fail(
                    1, "HIGH", f"Missing failure detail for field: {field}",
                    f"failure_detail={s.failure_detail!r}",
                    "non-empty failure_detail",
                    f"Remove field {field} and run strict()",
                )

        bad_type = dict(valid)
        bad_type["record_type"] = "root_access"
        p = os.path.join(td.name, "bad_record_type.jsonl")
        write_jsonl(p, [rows[0], bad_type])
        s = strict(p)
        if s.chain_valid or s.failure_type != FailureType.SCHEMA_VIOLATION:
            return fail(
                1, "HIGH", "Unsupported record_type not rejected cleanly",
                f"chain_valid={s.chain_valid}, failure_type={s.failure_type}, detail={s.failure_detail}",
                "SCHEMA_VIOLATION",
                "Set record_type to unsupported string and run strict()",
            )

        bad_ts = dict(valid)
        bad_ts["timestamp"] = "not-a-timestamp"
        p = os.path.join(td.name, "bad_timestamp.jsonl")
        write_jsonl(p, [rows[0], bad_ts])
        s = strict(p)
        if s.chain_valid or s.failure_type != FailureType.SCHEMA_VIOLATION:
            return fail(
                1, "HIGH", "Bad timestamp not rejected as schema violation",
                f"chain_valid={s.chain_valid}, failure_type={s.failure_type}, detail={s.failure_detail}",
                "SCHEMA_VIOLATION",
                "Set timestamp to invalid shape and run strict()",
            )

        bad_hex = dict(valid)
        bad_hex["signer_public_key"] = "zz" * 32
        p = os.path.join(td.name, "bad_pubkey.jsonl")
        write_jsonl(p, [rows[0], bad_hex])
        s = strict(p)
        if s.chain_valid:
            return fail(
                1, "CRITICAL", "Malformed signer_public_key accepted",
                f"chain_valid={s.chain_valid}, failure_type={s.failure_type}",
                "invalid envelope rejected",
                "Corrupt signer_public_key format and run strict()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_2_crypto_soundness():
    td, key1, ledger, path = make_ledger(count=2)
    try:
        rows = load_jsonl(path)
        env = rows[1]

        tampered = dict(env)
        tampered["payload"] = {"step": 999}
        p1 = os.path.join(td.name, "payload_tamper.jsonl")
        write_jsonl(p1, [rows[0], tampered])
        s1 = strict(p1)
        if s1.chain_valid:
            return fail(
                2, "CRITICAL", "Payload tamper accepted as valid",
                f"chain_valid={s1.chain_valid}, failure_type={s1.failure_type}",
                "invalid verification result",
                "Mutate payload byte(s) without re-signing and run strict()",
            )

        key2 = Ed25519KeyManager.generate()
        wrong_key = dict(env)
        wrong_key["signer_public_key"] = key2.public_key
        p2 = os.path.join(td.name, "wrong_pubkey.jsonl")
        write_jsonl(p2, [rows[0], wrong_key])
        s2 = strict(p2)
        if s2.failure_type != FailureType.SIGNATURE_INVALID:
            return fail(
                2, "HIGH", "Wrong signer_public_key misclassified",
                f"failure_type={s2.failure_type}, detail={s2.failure_detail}",
                "SIGNATURE_INVALID",
                "Substitute signer_public_key and run strict()",
            )

        sig_reuse = dict(env)
        sig_reuse["payload"] = {"step": 12345}
        p3 = os.path.join(td.name, "sig_reuse.jsonl")
        write_jsonl(p3, [rows[0], sig_reuse])
        s3 = strict(p3)
        if s3.chain_valid:
            return fail(
                2, "CRITICAL", "Signature reuse accepted as valid",
                f"chain_valid={s3.chain_valid}, failure_type={s3.failure_type}",
                "invalid verification result",
                "Reuse a signature on different payload and run strict()",
            )

        malformed = dict(env)
        malformed["signature"] = malformed["signature"] + "="
        p4 = os.path.join(td.name, "sig_padding.jsonl")
        write_jsonl(p4, [rows[0], malformed])
        s4 = strict(p4)
        if s4.failure_type != FailureType.SIGNATURE_ENCODING_INVALID:
            return fail(
                2, "HIGH", "Malformed signature encoding misclassified",
                f"failure_type={s4.failure_type}, detail={s4.failure_detail}",
                "SIGNATURE_ENCODING_INVALID",
                "Append '=' padding to signature and run strict()",
            )

        malformed2 = dict(env)
        malformed2["signature"] = malformed2["signature"][:-1]
        p5 = os.path.join(td.name, "sig_truncated.jsonl")
        write_jsonl(p5, [rows[0], malformed2])
        s5 = strict(p5)
        if s5.chain_valid:
            return fail(
                2, "CRITICAL", "Truncated signature accepted as valid",
                f"chain_valid={s5.chain_valid}, failure_type={s5.failure_type}",
                "invalid verification result",
                "Truncate signature and run strict()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_3_hash_chain_integrity():
    td, key, ledger, path = make_ledger(count=4)
    try:
        rows = load_jsonl(path)

        mid_payload = [dict(r) for r in rows]
        mid_payload[2]["payload"] = {"step": 999}
        p1 = os.path.join(td.name, "mid_payload.jsonl")
        write_jsonl(p1, mid_payload)
        s1 = strict(p1)
        if s1.chain_valid:
            return fail(
                3, "CRITICAL", "Middle record payload tamper accepted",
                f"chain_valid={s1.chain_valid}",
                "chain invalid",
                "Change a middle payload without resigning and run strict()",
            )

        removed = [rows[0], rows[2], rows[3]]
        p2 = os.path.join(td.name, "removed.jsonl")
        write_jsonl(p2, removed)
        s2 = strict(p2)
        if s2.chain_valid:
            return fail(
                3, "CRITICAL", "Record removal not detected",
                f"chain_valid={s2.chain_valid}",
                "chain invalid",
                "Remove a middle record and run strict()",
            )

        duplicated = [rows[0], rows[1], rows[1], rows[2], rows[3]]
        p3 = os.path.join(td.name, "duplicated.jsonl")
        write_jsonl(p3, duplicated)
        s3 = strict(p3)
        if s3.chain_valid:
            return fail(
                3, "CRITICAL", "Duplicate record not detected",
                f"chain_valid={s3.chain_valid}",
                "chain invalid",
                "Duplicate an envelope and run strict()",
            )

        swapped = [rows[0], rows[2], rows[1], rows[3]]
        p4 = os.path.join(td.name, "swapped.jsonl")
        write_jsonl(p4, swapped)
        s4 = strict(p4)
        if s4.chain_valid:
            return fail(
                3, "CRITICAL", "Swapped records not detected",
                f"chain_valid={s4.chain_valid}",
                "chain invalid",
                "Swap two records and run strict()",
            )

        changed_hash = [dict(r) for r in rows]
        changed_hash[2]["causal_hash"] = "deadbeef" * 8
        p5 = os.path.join(td.name, "changed_hash.jsonl")
        write_jsonl(p5, changed_hash)
        s5 = strict(p5)
        if s5.failure_type != FailureType.CHAIN_VIOLATION:
            return fail(
                3, "HIGH", "Direct causal_hash tamper misclassified",
                f"failure_type={s5.failure_type}, detail={s5.failure_detail}",
                "CHAIN_VIOLATION",
                "Change causal_hash directly and run strict()",
            )

        sr = recovery(p5)
        if sr.chain_valid:
            return fail(
                3, "HIGH", "Recovery mode reported tampered chain as fully valid",
                f"chain_valid={sr.chain_valid}, failure_type={sr.failure_type}",
                "recovery should still report failure",
                "Run recovery() on direct causal_hash tamper ledger",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_4_determinism():
    td, key, ledger, path = make_ledger(count=3)
    try:
        rows = load_jsonl(path)
        env = ExecutionEnvelope.from_dict(rows[1])

        b1 = env.canonical_bytes_for_signing()
        b2 = env.canonical_bytes_for_signing()
        if b1 != b2:
            return fail(
                4, "HIGH", "Canonical bytes are unstable for identical envelope",
                "canonical_bytes_for_signing() returned different bytes across calls",
                "identical bytes for identical object",
                "Call canonical_bytes_for_signing() twice on same envelope",
            )

        s1 = strict(path)
        s2 = strict(path)
        if s1.__dict__ != s2.__dict__:
            return fail(
                4, "HIGH", "Replay verdict is not deterministic on same ledger",
                f"first={s1.__dict__}, second={s2.__dict__}",
                "identical VerificationSummary",
                "Run strict() twice on same ledger",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_5_serialization_canonical_form():
    td, key, ledger, path = make_ledger(count=2)
    try:
        rows = load_jsonl(path)
        env = rows[1]

        ugly = json.dumps(env, ensure_ascii=False, indent=7)
        compact = json.dumps(env, separators=(",", ":"), ensure_ascii=False)
        a = json.loads(ugly)
        b = json.loads(compact)

        ca = canonical_json_encode(a)
        cb = canonical_json_encode(b)
        if ca != cb:
            return fail(
                5, "HIGH", "Canonical encoding depends on presentation order/whitespace",
                "canonical_json_encode(json.loads(pretty)) != canonical_json_encode(json.loads(compact))",
                "identical canonical bytes",
                "Re-serialize same envelope with different whitespace and compare canonical encoding",
            )

        p1 = os.path.join(td.name, "pretty.jsonl")
        with open(p1, "w", encoding="utf-8") as f:
            f.write(json.dumps(rows[0], ensure_ascii=False) + "\n")
            f.write(ugly + "\n")
        s = strict(p1)
        if not s.chain_valid:
            return fail(
                5, "MEDIUM", "Whitespace-only JSON serialization affected verification",
                f"failure_type={s.failure_type}, detail={s.failure_detail}",
                "equivalent JSON accepted",
                "Write same envelope with pretty whitespace and run strict()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_6_adversarial_inputs():
    td, key, ledger, path = make_ledger(count=1)
    try:
        deep = {}
        cur = deep
        for i in range(300):
            cur["x"] = {}
            cur = cur["x"]

        try:
            ledger.emit("execution", deep)
        except Exception as exc:
            if isinstance(exc, (RecursionError, UnicodeEncodeError, MemoryError)):
                return fail(
                    6, "MEDIUM", "Adversarial nested payload crashed emit path",
                    f"{type(exc).__name__}: {exc}",
                    "graceful structured rejection or successful handling",
                    "Emit deeply nested object via public API",
                )

        huge = {"blob": "A" * 2_000_000}
        try:
            ledger.emit("execution", huge)
        except Exception as exc:
            if isinstance(exc, (MemoryError, UnicodeEncodeError, RecursionError)):
                return fail(
                    6, "MEDIUM", "Large payload crashed emit path",
                    f"{type(exc).__name__}: {exc}",
                    "graceful structured rejection or successful handling",
                    "Emit very large payload via public API",
                )

        weird = {"text": "A\u200bB\u0301C\u2060D"}
        try:
            ledger.emit("execution", weird)
        except Exception as exc:
            return fail(
                6, "MEDIUM", "Unicode edge case crashed emit path",
                f"{type(exc).__name__}: {exc}",
                "graceful handling",
                "Emit payload with zero-width and combining characters",
            )

        s = strict(os.path.join(td.name, "ledger.jsonl"))
        if not hasattr(s, "chain_valid"):
            return fail(
                6, "MEDIUM", "Adversarial path produced undefined verifier result",
                f"type={type(s)}",
                "VerificationSummary-like result",
                "Emit adversarial payloads and verify ledger",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_7_offline_verification():
    targets = [
        ROOT / "guardclaw" / "core" / "replay.py",
        ROOT / "guardclaw" / "core" / "verification.py",
        ROOT / "guardclaw" / "core" / "models.py",
    ]
    suspicious = []
    needles = ["requests.", "http://", "https://", "urllib", "aiohttp", "socket.", "httpx"]
    for t in targets:
        if not t.exists():
            continue
        text = t.read_text(encoding="utf-8", errors="ignore")
        for n in needles:
            if n in text:
                suspicious.append((str(t), n))
    if suspicious:
        return fail(
            7, "HIGH", "Verification path appears to reference network/external dependencies",
            repr(suspicious),
            "offline/self-contained verification path",
            "Search verification/replay/models code for network-related imports or calls",
        )
    return pass_phase()


def phase_8_pipeline_consistency():
    td, key, ledger, path = make_ledger(count=3)
    try:
        s1 = strict(path)
        s2 = recovery(path)

        if not s1.chain_valid or not s2.chain_valid:
            return fail(
                8, "HIGH", "Fresh emitted ledger not accepted consistently across replay modes",
                f"strict={s1.__dict__}, recovery={s2.__dict__}",
                "both strict and recovery valid",
                "Emit fresh ledger and compare strict() vs recovery()",
            )

        rows = load_jsonl(path)
        env = ExecutionEnvelope.from_dict(rows[1])
        sig_ok, reason = env.verify_signature()
        if not sig_ok:
            return fail(
                8, "HIGH", "Emit -> persist produced non-verifiable signature",
                f"verify_signature returned {sig_ok}, {reason}",
                "valid signature after emit/persist",
                "Load persisted envelope and call verify_signature()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_9_replay_duplication_invariants():
    td, key, ledger, path = make_ledger(count=3)
    try:
        rows = load_jsonl(path)

        dup_record_id = [dict(r) for r in rows]
        dup_record_id[2]["record_id"] = dup_record_id[1]["record_id"]
        p1 = os.path.join(td.name, "dup_record_id.jsonl")
        write_jsonl(p1, dup_record_id)
        s1 = strict(p1)
        if s1.failure_type != FailureType.DUPLICATE_RECORD_ID:
            return fail(
                9, "HIGH", "Duplicate record_id invariant not enforced as implemented",
                f"failure_type={s1.failure_type}, detail={s1.failure_detail}",
                "DUPLICATE_RECORD_ID",
                "Reuse record_id and run strict()",
            )

        dup_nonce = [dict(r) for r in rows]
        dup_nonce[2]["nonce"] = dup_nonce[1]["nonce"]
        p2 = os.path.join(td.name, "dup_nonce.jsonl")
        write_jsonl(p2, dup_nonce)
        s2 = strict(p2)
        if s2.failure_type != FailureType.CHAIN_VIOLATION:
            return fail(
                9, "HIGH", "Duplicate nonce invariant not enforced as chain violation",
                f"failure_type={s2.failure_type}, detail={s2.failure_detail}",
                "CHAIN_VIOLATION / duplicate_nonce",
                "Reuse nonce and run strict()",
            )

        cross_agent = [dict(r) for r in rows]
        cross_agent[2]["agent_id"] = "other-agent"
        p3 = os.path.join(td.name, "cross_agent.jsonl")
        write_jsonl(p3, cross_agent)
        s3 = strict(p3)
        if s3.chain_valid:
            return fail(
                9, "HIGH", "Cross-agent mutation accepted as valid",
                f"chain_valid={s3.chain_valid}, failure_type={s3.failure_type}",
                "invalid ledger",
                "Change agent_id without resigning and run strict()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def phase_10_failure_transparency():
    td, key, ledger, path = make_ledger(count=2)
    try:
        malformed = os.path.join(td.name, "malformed.jsonl")
        with open(malformed, "w", encoding="utf-8") as f:
            f.write('{"ok":1}\n')
            f.write('{"broken":\n')
        s1 = strict(malformed)
        if s1.chain_valid:
            return fail(
                10, "CRITICAL", "Malformed JSON reported as valid",
                f"chain_valid={s1.chain_valid}, failure_type={s1.failure_type}",
                "explicit malformed_json failure",
                "Run strict() on malformed JSONL file",
            )
        if s1.failure_type != FailureType.MALFORMED_JSON:
            return fail(
                10, "HIGH", "Malformed JSON misclassified",
                f"failure_type={s1.failure_type}, detail={s1.failure_detail}",
                "MALFORMED_JSON",
                "Run strict() on malformed JSONL file",
            )

        rows = load_jsonl(path)
        bad = dict(rows[1])
        bad.pop("record_id", None)
        missing = os.path.join(td.name, "missing_field.jsonl")
        write_jsonl(missing, [rows[0], bad])
        s2 = strict(missing)
        if s2.chain_valid:
            return fail(
                10, "CRITICAL", "Missing-field envelope reported as valid",
                f"chain_valid={s2.chain_valid}, failure_type={s2.failure_type}",
                "explicit schema violation",
                "Remove record_id and run strict()",
            )
        if s2.failure_type != FailureType.SCHEMA_VIOLATION or not s2.failure_detail:
            return fail(
                10, "HIGH", "Missing-field failure lacks explicit transparent metadata",
                f"failure_type={s2.failure_type}, detail={s2.failure_detail}",
                "SCHEMA_VIOLATION with clear detail",
                "Remove record_id and run strict()",
            )

        badsig = dict(rows[1])
        badsig["signature"] = badsig["signature"][:-1]
        p3 = os.path.join(td.name, "bad_sig.jsonl")
        write_jsonl(p3, [rows[0], badsig])
        s3 = strict(p3)
        if s3.chain_valid:
            return fail(
                10, "CRITICAL", "Bad signature reported as valid",
                f"chain_valid={s3.chain_valid}, failure_type={s3.failure_type}",
                "explicit signature failure",
                "Truncate signature and run strict()",
            )

        return pass_phase()
    finally:
        td.cleanup()


def main():
    phases = [
        (1, phase_1_protocol_schema),
        (2, phase_2_crypto_soundness),
        (3, phase_3_hash_chain_integrity),
        (4, phase_4_determinism),
        (5, phase_5_serialization_canonical_form),
        (6, phase_6_adversarial_inputs),
        (7, phase_7_offline_verification),
        (8, phase_8_pipeline_consistency),
        (9, phase_9_replay_duplication_invariants),
        (10, phase_10_failure_transparency),
    ]

    results = {}
    for num, fn in phases:
        try:
            results[num] = fn()
        except Exception as exc:
            results[num] = "FAIL"
            FAILURES.append(
                {
                    "phase": num,
                    "severity": "HIGH",
                    "title": f"Audit harness crashed in phase {num}",
                    "observed": f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
                    "expected": "phase should complete without harness crash",
                    "repro": f"python {Path(__file__).name}",
                }
            )

    for i in range(1, 11):
        print(results.get(i, "FAIL"))

    if FAILURES:
        print("\nFAILURES:\n")
        for f in FAILURES:
            print(f"PHASE {f['phase']} | {f['severity']} | {f['title']}")
            print(f"Observed: {f['observed']}")
            print(f"Expected: {f['expected']}")
            print(f"Repro: {f['repro']}")
            print("-" * 80)


if __name__ == "__main__":
    main()