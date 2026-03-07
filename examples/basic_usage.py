from pathlib import Path
from guardclaw.core.modes import init_ghost_mode
from guardclaw.core.observers import Observer

def main():
    mode_manager = init_ghost_mode()
    ledger_path = Path(".guardclaw/ledger/test.jsonl")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger = mode_manager.create_ledger(ledger_path=ledger_path, signer_id="agent-001")
    obs = Observer(agent_id="agent-001", ledger=ledger)
    obs.on_intent("test intent")
    obs.on_execution("test action")
    obs.on_result("test action", "done")
    print("OK - ledger written to", ledger_path)

if __name__ == "__main__":
    main()