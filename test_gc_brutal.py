from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
import os

print("RUNNING FILE:", os.path.abspath(__file__))

# Generate key
key = Ed25519KeyManager.generate()

print("PUBLIC KEY:")
print(key.public_key_hex)

ledger_path = "ledger_brutal_test_unique"
print("USING LEDGER PATH:", ledger_path)

ledger = GEFLedger(
    key_manager=key,
    agent_id="agent-brutal-test",
    ledger_path=ledger_path,
    mode="strict",
)

# Emit events
for i in range(5):
    ledger.emit(
        RecordType.EXECUTION,
        payload={"step": i}
    )

ledger.close()

print("\nLedger created")