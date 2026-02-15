"""
Ledger implementation for GuardClaw.

ALIGNED TO: Canonical schema v1.1
"""

import json
import hashlib
import os
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

from guardclaw.core.models import (
    AuthorizationProof,
    ExecutionReceipt,
    SettlementRecord,
    utc_now,
)
from guardclaw.core.crypto import SigningKey
from guardclaw.core.exceptions import LedgerError


@dataclass
class LedgerEntry:
    """A single entry in the ledger"""
    index: int
    previous_hash: str
    timestamp: datetime
    entry_type: str
    data: dict
    data_hash: bytes
    signature: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp.isoformat(),
            "entry_type": self.entry_type,
            "data": self.data,
            "data_hash": self.data_hash.hex(),  # Convert bytes to hex string
            "signature": self.signature,
        }
    
    @staticmethod
    def from_dict(data: dict) -> "LedgerEntry":
        """Create entry from dictionary"""
        return LedgerEntry(
            index=data["index"],
            previous_hash=data["previous_hash"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            entry_type=data["entry_type"],
            data=data["data"],
            data_hash=bytes.fromhex(data["data_hash"]),  # Convert hex string back to bytes
            signature=data["signature"],
        )
    
    def compute_hash(self) -> str:
        """Compute hash of this entry for chaining"""
        hash_input = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp.isoformat(),
            "entry_type": self.entry_type,
            "data_hash": self.data_hash.hex(),
        }
        
        json_str = json.dumps(hash_input, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()


class Ledger:
    """
    Append-only cryptographic ledger.
    
    CANONICAL COMPLIANCE: Stores canonical v1.1 models.
    """
    
    GENESIS_HASH = "0" * 64
    
    def __init__(self, ledger_path: Path, signing_key: SigningKey):
        self.ledger_path = Path(ledger_path)
        self.signing_key = signing_key
        self.entries: List[LedgerEntry] = []
        
        # Load existing ledger if it exists
        if self.ledger_path.exists():
            self._load()
            self.verify_or_raise()
    
    def append_authorization(self, proof: AuthorizationProof) -> LedgerEntry:
        """Append an authorization proof to the ledger"""
        entry = self._create_entry(
            entry_type="authorization",
            data=proof.to_dict(),
        )
        return entry
    
    def append_receipt(self, receipt: ExecutionReceipt) -> LedgerEntry:
        """Append an execution receipt to the ledger"""
        entry = self._create_entry(
            entry_type="receipt",
            data=receipt.to_dict(),
        )
        return entry
    
    def append_settlement(self, settlement: SettlementRecord) -> LedgerEntry:
        """Append a settlement record to the ledger"""
        entry = self._create_entry(
            entry_type="settlement",
            data=settlement.to_dict(),
        )
        return entry
    
    def get_all_entries(self) -> List[LedgerEntry]:
        """Get all ledger entries"""
        return self.entries.copy()
    
    def get_entry_by_index(self, index: int) -> Optional[LedgerEntry]:
        """Get entry by index"""
        if 0 <= index < len(self.entries):
            return self.entries[index]
        return None
    
    def get_authorization_by_proof_id(self, proof_id: str) -> Optional[LedgerEntry]:
        """Find authorization entry by proof_id"""
        for entry in self.entries:
            if entry.entry_type == "authorization" and entry.data.get("proof_id") == proof_id:
                return entry
        return None
    
    def get_entries_by_type(self, entry_type: str) -> List[LedgerEntry]:
        """Get all entries of a specific type"""
        return [e for e in self.entries if e.entry_type == entry_type]
    
    def get_stats(self) -> dict:
        """Get ledger statistics"""
        type_counts = {}
        for entry in self.entries:
            type_counts[entry.entry_type] = type_counts.get(entry.entry_type, 0) + 1
        
        return {
            "total_entries": len(self.entries),
            "by_type": type_counts,
            "first_entry_time": self.entries[0].timestamp.isoformat() if self.entries else None,
            "last_entry_time": self.entries[-1].timestamp.isoformat() if self.entries else None,
        }
    
    def verify_or_raise(self) -> None:
        """Verify ledger integrity or raise exception"""
        if not self.entries:
            return
        
        # Verify first entry links to genesis
        if self.entries[0].previous_hash != self.GENESIS_HASH:
            raise LedgerError("First entry does not link to genesis hash")
        
        # Verify chain linkage
        for i in range(1, len(self.entries)):
            prev_entry = self.entries[i - 1]
            curr_entry = self.entries[i]
            
            expected_prev_hash = prev_entry.compute_hash()
            if curr_entry.previous_hash != expected_prev_hash:
                raise LedgerError(
                    f"Chain break at index {i}: "
                    f"expected {expected_prev_hash}, got {curr_entry.previous_hash}"
                )
        
        # Verify signatures
        for entry in self.entries:
            entry_hash_bytes = bytes.fromhex(entry.compute_hash())
            if not self.signing_key.verify(entry_hash_bytes, entry.signature):
                raise LedgerError(f"Invalid signature at index {entry.index}")
    
    def _create_entry(self, entry_type: str, data: dict) -> LedgerEntry:
        """Create and append a new entry"""
        index = len(self.entries)
        previous_hash = self.entries[-1].compute_hash() if self.entries else self.GENESIS_HASH
        timestamp = utc_now()
        
        # Hash the data
        data_json = json.dumps(data, sort_keys=True, default=str)
        data_hash = hashlib.sha256(data_json.encode()).digest()
        
        # Create entry (unsigned)
        entry = LedgerEntry(
            index=index,
            previous_hash=previous_hash,
            timestamp=timestamp,
            entry_type=entry_type,
            data=data,
            data_hash=data_hash,
            signature="",
        )
        
        # Sign entry
        entry_hash_bytes = bytes.fromhex(entry.compute_hash())
        signature = self.signing_key.sign(entry_hash_bytes)
        
        # Create signed entry
        signed_entry = LedgerEntry(
            index=entry.index,
            previous_hash=entry.previous_hash,
            timestamp=entry.timestamp,
            entry_type=entry.entry_type,
            data=entry.data,
            data_hash=entry.data_hash,
            signature=signature,
        )
        
        # Append to memory and disk
        self.entries.append(signed_entry)
        self._write_entry(signed_entry)
        
        return signed_entry
    
    def _write_entry(self, entry: LedgerEntry) -> None:
        """Write entry to disk atomically"""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        temp_path = self.ledger_path.with_suffix('.tmp')
        
        try:
            with open(temp_path, 'a', encoding='utf-8') as f:
                json.dump(entry.to_dict(), f, ensure_ascii=False)
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            
            if not self.ledger_path.exists():
                temp_path.rename(self.ledger_path)
            else:
                with open(temp_path, 'r', encoding='utf-8') as temp_f:
                    with open(self.ledger_path, 'a', encoding='utf-8') as main_f:
                        main_f.write(temp_f.read())
                        main_f.flush()
                        os.fsync(main_f.fileno())
                temp_path.unlink()
        
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            raise LedgerError(f"Failed to write ledger entry: {e}")
    
    def _load(self) -> None:
        """Load ledger from disk"""
        self.entries = []
        
        try:
            with open(self.ledger_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        entry_data = json.loads(line)
                        entry = LedgerEntry.from_dict(entry_data)
                        self.entries.append(entry)
                    except json.JSONDecodeError as e:
                        raise LedgerError(f"Invalid JSON at line {line_num}: {e}")
        
        except FileNotFoundError:
            pass
        except Exception as e:
            raise LedgerError(f"Failed to load ledger: {e}")
