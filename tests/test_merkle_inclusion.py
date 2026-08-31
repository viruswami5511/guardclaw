"""
tests/test_merkle_inclusion.py

Validates RFC 6962 Merkle Tree generation, root hashing, audit path construction,
and O(log N) inclusion proof verification for GuardClaw ledgers.
"""

import tempfile
from pathlib import Path

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.merkle import MerkleTree, MerkleInclusionProof
from guardclaw.core.models import RecordType


def test_merkle_tree_construction_and_inclusion():
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        ledger = GEFLedger(key_manager=key, agent_id="merkle-agent", ledger_path=td)
        emitted_ids = []
        for i in range(15):
            env = ledger.emit(RecordType.EXECUTION, {"step": i, "action": "test.op"})
            emitted_ids.append(env.record_id)

        ledger_file = Path(td) / "ledger.jsonl"
        tree = MerkleTree.from_ledger_file(ledger_file)

        assert tree.root_hash
        assert len(tree.root_hash) == 64

        # Test inclusion proof for every record
        for idx, rec_id in enumerate(emitted_ids):
            proof = tree.get_inclusion_proof_by_record_id(rec_id)
            assert proof.record_id == rec_id
            assert proof.verify(expected_root=tree.root_hash) is True

            # Negative test: Tampering with leaf hash breaks proof
            bad_proof = MerkleInclusionProof(
                record_id=proof.record_id,
                sequence=proof.sequence,
                leaf_hash="0" * 64,
                root_hash=proof.root_hash,
                total_leaves=proof.total_leaves,
                audit_path=proof.audit_path,
            )
            assert bad_proof.verify() is False

            # Serialization roundtrip test
            d = proof.to_dict()
            restored = MerkleInclusionProof.from_dict(d)
            assert restored.verify() is True
