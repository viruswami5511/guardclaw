from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from guardclaw.core.replay import ReplayEngine

PROTOCOL_VERSION = "1.0"


def build_summary_from_engine(
    engine: ReplayEngine,
    ledger_path: str | Path,
    verification_summary: Any | None = None,
) -> Dict[str, Any]:
    """
    Build a stable summary from a ReplayEngine.
    """

    path = Path(ledger_path)

    # Use provided summary or compute
    replay_summary = (
        verification_summary if verification_summary is not None else engine.verify()
    )

    violations: List[Dict[str, Any]] = []
    for v in getattr(replay_summary, "violations", []) or []:
        violations.append(
            {
                "sequence": getattr(v, "at_sequence", None),
                "record_id": getattr(v, "record_id", None),
                "violation_type": getattr(v, "violation_type", None),
                "detail": getattr(v, "detail", None),
            }
        )

    entries: List[Dict[str, Any]] = [
        {
            "sequence": env.sequence,
            "record_type": env.record_type.value if hasattr(env.record_type, "value") else env.record_type,
            "timestamp": env.timestamp,
            "record_id": env.record_id,
            "causal_hash": env.causal_hash,
            "trigger_hash": None,
        }
        for env in engine.envelopes
    ]

    verified_count = getattr(replay_summary, "verified_count", len(entries))
    total_entries = getattr(replay_summary, "total_entries", len(entries))
    partial_integrity = getattr(replay_summary, "partial_integrity", False)
    chain_valid = getattr(replay_summary, "chain_valid", False)

    # 🔒 Protocol invariant: no INVALID allowed here
    if not chain_valid and not partial_integrity:
        raise RuntimeError("Invalid ledger cannot produce summary")

    integrity_status = "FULL" if chain_valid else "PARTIAL"

    first_timestamp = entries[0]["timestamp"] if entries else None
    last_timestamp = entries[-1]["timestamp"] if entries else None

    agent_ids = sorted(
        {env.agent_id for env in engine.envelopes if getattr(env, "agent_id", None)}
    )

    gef_version = engine.envelopes[0].gef_version if engine.envelopes else None

    return {
        "protocol_version": PROTOCOL_VERSION,
        "integrity_status": integrity_status,
        "chain_valid": chain_valid,
        "partial_integrity": partial_integrity,
        "verified_count": verified_count,
        "total_entries": total_entries,
        "violations": violations,
        "agent_ids": agent_ids,
        "gef_version": gef_version,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "ledger_path": str(path.resolve()),
        "entries": entries,
        "recovery_mode_active": getattr(replay_summary, "recovery_mode_active", False),
        "failure_sequence": getattr(replay_summary, "failure_sequence", None),
        "failure_type": str(getattr(replay_summary, "failure_type", None))
        if getattr(replay_summary, "failure_type", None)
        else None,
        "failure_detail": getattr(replay_summary, "failure_detail", None),
        "integrity_boundary_hash": getattr(replay_summary, "integrity_boundary_hash", None),
        "boundary_sequence": getattr(replay_summary, "boundary_sequence", None),
    }


def build_summary(ledger_path: str | Path) -> Dict[str, Any]:
    """
    Convenience wrapper.
    """
    path = Path(ledger_path)

    if not path.exists():
        raise FileNotFoundError(f"Ledger not found: {ledger_path}")

    engine = ReplayEngine(parallel=False, silent=True)
    engine.load(path)

    return build_summary_from_engine(engine, path)