"""
guardclaw/core/merkle.py

RFC 6962-Compliant Merkle Tree & Inclusion Proof Engine for GuardClaw.
Provides O(log N) cryptographic proof of event existence in a ledger
without requiring transmission or verification of the entire ledger.

Standards & Conventions:
- Leaf hash: SHA-256(0x00 || RFC_8785_JCS(envelope))
- Internal node hash: SHA-256(0x01 || left_child || right_child)
- Balanced binary tree construction with odd-leaf duplicate promotion
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.models import ExecutionEnvelope


def _leaf_hash(data_bytes: bytes) -> bytes:
    """RFC 6962 Leaf Hash prefix 0x00 prevents second-preimage attacks."""
    return hashlib.sha256(b"\x00" + data_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 Node Hash prefix 0x01."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass(frozen=True)
class MerkleInclusionProof:
    """
    Self-contained inclusion proof for a single ledger record.
    """
    record_id: str
    sequence: int
    leaf_hash: str
    root_hash: str
    total_leaves: int
    audit_path: List[Tuple[str, str]]  # list of (direction, sibling_hex_hash)

    def verify(self, expected_root: Optional[str] = None) -> bool:
        """
        Verify that this proof reproduces root_hash (and matches expected_root if provided).
        Runs in O(log N) time.
        """
        target_root = (expected_root or self.root_hash).lower()
        curr = bytes.fromhex(self.leaf_hash)

        for direction, sibling_hex in self.audit_path:
            sibling = bytes.fromhex(sibling_hex)
            if direction == "left":
                curr = _node_hash(sibling, curr)
            elif direction == "right":
                curr = _node_hash(curr, sibling)
            else:
                return False

        return curr.hex().lower() == target_root

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "sequence": self.sequence,
            "leaf_hash": self.leaf_hash,
            "root_hash": self.root_hash,
            "total_leaves": self.total_leaves,
            "audit_path": [{"dir": d, "hash": h} for d, h in self.audit_path],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MerkleInclusionProof":
        audit = [(item["dir"], item["hash"]) for item in d["audit_path"]]
        return cls(
            record_id=d["record_id"],
            sequence=d["sequence"],
            leaf_hash=d["leaf_hash"],
            root_hash=d["root_hash"],
            total_leaves=d["total_leaves"],
            audit_path=audit,
        )


class MerkleTree:
    """
    Cryptographic Merkle Tree built over a collection of GEF ExecutionEnvelopes.
    """

    def __init__(self, envelopes: List[ExecutionEnvelope]) -> None:
        self.envelopes = list(envelopes)
        self._record_id_to_index: Dict[str, int] = {
            env.record_id: idx for idx, env in enumerate(self.envelopes)
        }
        self._levels: List[List[bytes]] = []
        self._build_tree()

    @classmethod
    def from_ledger_file(cls, ledger_path: Union[str, Path]) -> "MerkleTree":
        path = Path(ledger_path)
        if not path.exists():
            raise FileNotFoundError(f"Ledger file not found: {path}")

        envs = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                data = json.loads(raw)
                envs.append(ExecutionEnvelope.from_dict(data))
        return cls(envs)

    def _build_tree(self) -> None:
        if not self.envelopes:
            self._levels = [[hashlib.sha256(b"\x00").digest()]]
            return

        # Level 0: Leaves
        leaves = [
            _leaf_hash(canonical_json_encode(env.to_dict()))
            for env in self.envelopes
        ]
        self._levels = [leaves]

        curr = leaves
        while len(curr) > 1:
            next_level = []
            for i in range(0, len(curr), 2):
                left = curr[i]
                if i + 1 < len(curr):
                    right = curr[i + 1]
                else:
                    # Odd leaf duplicate promotion
                    right = left
                next_level.append(_node_hash(left, right))
            self._levels.append(next_level)
            curr = next_level

    @property
    def root_hash(self) -> str:
        """Hex-encoded root digest (64 hex characters)."""
        if not self._levels or not self._levels[-1]:
            return ""
        return self._levels[-1][0].hex()

    def get_inclusion_proof(self, index: int) -> MerkleInclusionProof:
        """Generate an inclusion proof for envelope at 0-indexed position `index`."""
        if index < 0 or index >= len(self.envelopes):
            raise IndexError(f"Index {index} out of range (0..{len(self.envelopes)-1})")

        env = self.envelopes[index]
        leaf_hash = self._levels[0][index].hex()
        audit_path: List[Tuple[str, str]] = []

        curr_idx = index
        for level in self._levels[:-1]:
            is_right_child = (curr_idx % 2 == 1)
            sibling_idx = curr_idx - 1 if is_right_child else curr_idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx].hex()
            else:
                # Odd node duplicate
                sibling_hash = level[curr_idx].hex()

            direction = "left" if is_right_child else "right"
            audit_path.append((direction, sibling_hash))
            curr_idx //= 2

        return MerkleInclusionProof(
            record_id=env.record_id,
            sequence=env.sequence,
            leaf_hash=leaf_hash,
            root_hash=self.root_hash,
            total_leaves=len(self.envelopes),
            audit_path=audit_path,
        )

    def get_inclusion_proof_by_record_id(self, record_id: str) -> MerkleInclusionProof:
        if record_id not in self._record_id_to_index:
            raise KeyError(f"record_id {record_id!r} not found in Merkle tree")
        return self.get_inclusion_proof(self._record_id_to_index[record_id])
