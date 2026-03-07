from guardclaw.core.emitter import get_global_ledger
from guardclaw.core.models import ExecutionEnvelope, RecordType
from guardclaw.core.time import gef_timestamp


def get_ledger():
    return get_global_ledger()


def record_action(agent_id: str, action: str, result: str, metadata=None) -> ExecutionEnvelope:
    """
    Record a signed agent action.
    Primary entry point for framework adapters.
    """
    ledger = get_global_ledger()

    return ledger.emit(
        record_type=RecordType.EXECUTION,
        payload={
            "agent_id": agent_id,
            "action": action,
            "result": result,
            "metadata": metadata or {},
            "timestamp": gef_timestamp(),
        }
    )


def verify_ledger(ledger_path: str):
    """Verify a GuardClaw ledger file."""
    from guardclaw.verification.verify import verify_ledger_file
    return verify_ledger_file(ledger_path)