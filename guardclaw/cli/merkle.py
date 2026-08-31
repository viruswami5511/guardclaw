"""
guardclaw/cli/merkle.py

guardclaw prove-inclusion / verify-inclusion — Merkle Tree Cryptographic Inclusion Proofs
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
import click

from guardclaw.core.merkle import MerkleTree, MerkleInclusionProof


@click.command(name="prove-inclusion")
@click.argument("ledger", type=click.Path(exists=True))
@click.option("--record-id", required=True, help="Record ID (e.g. gef-uuid) to prove inclusion for.")
@click.option("--format", "fmt", type=click.Choice(["json", "human"]), default="human", show_default=True)
def prove_inclusion_command(ledger: str, record_id: str, fmt: str) -> None:
    """
    Generate an O(log N) Merkle cryptographic inclusion proof for a ledger record.
    """
    try:
        tree = MerkleTree.from_ledger_file(Path(ledger))
        proof = tree.get_inclusion_proof_by_record_id(record_id)
        if fmt == "json":
            click.echo(json.dumps(proof.to_dict(), indent=2))
        else:
            click.echo(f"\n✅ Merkle Inclusion Proof Generated")
            click.echo(f"  Record ID   : {proof.record_id}")
            click.echo(f"  Sequence    : {proof.sequence}")
            click.echo(f"  Leaf Hash   : {proof.leaf_hash}")
            click.echo(f"  Root Hash   : {proof.root_hash}")
            click.echo(f"  Tree Leaves : {proof.total_leaves}")
            click.echo(f"  Proof Path  : {len(proof.audit_path)} steps (O(log N))\n")
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@click.command(name="verify-inclusion")
@click.argument("proof_file", type=click.Path(exists=True))
@click.option("--root-hash", required=False, help="Expected Merkle root hash (optional).")
def verify_inclusion_command(proof_file: str, root_hash: Optional[str]) -> None:
    """
    Verify an exported Merkle inclusion proof file against a root hash.
    """
    try:
        data = json.loads(Path(proof_file).read_text(encoding="utf-8"))
        proof = MerkleInclusionProof.from_dict(data)
        is_valid = proof.verify(expected_root=root_hash)
        if is_valid:
            click.echo(f"\n✅ Inclusion Proof Valid: Record {proof.record_id} is proven in root {proof.root_hash}\n")
            raise SystemExit(0)
        else:
            click.echo(f"\n❌ Inclusion Proof Invalid\n")
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
