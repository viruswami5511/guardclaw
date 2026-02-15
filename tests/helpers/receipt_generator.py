"""
Helper script to generate properly signed execution receipts.

This simulates a trusted execution environment that:
1. Receives authorization proof
2. Executes the action
3. Generates signed execution receipt

Usage:
    python tests/helpers/receipt_generator.py \
        --proof proof_12345.json \
        --status SUCCESS \
        --key guardclaw.key \
        --output receipt_12345.json

✅ Generates receipts with proper signatures
✅ Aligns with Day 1 ExecutionReceipt model
"""

import sys
import json
import uuid
import argparse
from pathlib import Path
from datetime import datetime

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guardclaw.core.models import ExecutionReceipt, ActionType
from guardclaw.core.crypto import SigningKey


def generate_receipt(
    proof_file: Path,
    status: str,
    key_file: Path,
    output_file: Path,
    error_message: str = None,
    executor_id: str = "test-executor",
):
    """
    Generate a properly signed execution receipt.
    
    Args:
        proof_file: Path to authorization proof JSON
        status: Execution status (SUCCESS or FAILURE)
        key_file: Path to signing key
        output_file: Path to save receipt
        error_message: Error message if status is FAILURE
        executor_id: Identifier of the executor
    """
    # Load proof
    with open(proof_file, 'r') as f:
        proof_data = json.load(f)
    
    # Load key
    with open(key_file, 'r') as f:
        key_hex = f.read().strip()
    key = SigningKey(bytes.fromhex(key_hex))
    
    # Create receipt
    receipt = ExecutionReceipt(
        receipt_id=str(uuid.uuid4()),
        proof_id=proof_data["proof_id"],
        observed_action_type=ActionType(proof_data["allowed_action_type"]),
        observed_target=proof_data["allowed_target"],
        observed_operation=proof_data["allowed_operation"],
        status=status,
        executed_at=datetime.now().astimezone(),
        executor_id=executor_id,
        error_message=error_message,
    )
    
    # Sign receipt
    receipt_hash = receipt.hash()
    signature = key.sign(receipt_hash)
    
    # Create signed receipt
    signed_receipt = ExecutionReceipt(
        receipt_id=receipt.receipt_id,
        proof_id=receipt.proof_id,
        observed_action_type=receipt.observed_action_type,
        observed_target=receipt.observed_target,
        observed_operation=receipt.observed_operation,
        status=receipt.status,
        executed_at=receipt.executed_at,
        executor_id=receipt.executor_id,
        error_message=receipt.error_message,
        signature=signature,
    )
    
    # Save to file
    with open(output_file, 'w') as f:
        json.dump(signed_receipt.to_dict(), f, indent=2, default=str)
    
    print(f"✅ Receipt generated: {output_file}")
    print(f"   Receipt ID: {signed_receipt.receipt_id}")
    print(f"   Proof ID: {signed_receipt.proof_id}")
    print(f"   Status: {signed_receipt.status}")
    print(f"   Signature: {signed_receipt.signature[:32]}...")


def main():
    parser = argparse.ArgumentParser(
        description="Generate signed execution receipt"
    )
    parser.add_argument(
        "--proof",
        type=Path,
        required=True,
        help="Path to authorization proof JSON",
    )
    parser.add_argument(
        "--status",
        choices=["SUCCESS", "FAILURE"],
        default="SUCCESS",
        help="Execution status",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=Path("guardclaw.key"),
        help="Path to signing key",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for receipt JSON",
    )
    parser.add_argument(
        "--error",
        type=str,
        default=None,
        help="Error message (if status is FAILURE)",
    )
    parser.add_argument(
        "--executor-id",
        type=str,
        default="test-executor",
        help="Executor identifier",
    )
    
    args = parser.parse_args()
    
    generate_receipt(
        proof_file=args.proof,
        status=args.status,
        key_file=args.key,
        output_file=args.output,
        error_message=args.error,
        executor_id=args.executor_id,
    )


if __name__ == "__main__":
    main()
