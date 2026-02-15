"""
GuardClaw Phase 5: Evidence Emitter

Async evidence emission with:
- Non-blocking queue
- Batch signing
- Write-ahead buffer (crash recovery)
- Graceful degradation
"""

import json
import threading
import time
from pathlib import Path
from queue import Queue, Full, Empty
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from dataclasses import dataclass

from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode
from guardclaw.core.observers import ObservationEvent


@dataclass
class SignedObservation:
    """Signed observation event."""
    event: ObservationEvent
    signature: str
    accountability_lag_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "signature": self.signature,
            "accountability_lag_ms": self.accountability_lag_ms
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedObservation":
        return cls(
            event=ObservationEvent.from_dict(data["event"]),
            signature=data["signature"],
            accountability_lag_ms=data["accountability_lag_ms"]
        )


class WriteAheadBuffer:
    """
    Write-ahead buffer for crash recovery.
    
    Events are written to pending.jsonl immediately.
    After signing, moved to signed.jsonl and removed from pending.
    """
    
    def __init__(self, buffer_dir: Path):
        self.buffer_dir = Path(buffer_dir)
        self.buffer_dir.mkdir(parents=True, exist_ok=True)
        
        self.pending_file = self.buffer_dir / "pending.jsonl"
        self.signed_file = self.buffer_dir / "signed.jsonl"
    
    def append_pending(self, event: ObservationEvent) -> None:
        """Append event to pending buffer (best-effort)."""
        try:
            with open(self.pending_file, 'a') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception:
            pass  # Best-effort, don't crash
    
    def append_signed(self, signed_obs: SignedObservation) -> None:
        """Append signed observation to signed buffer."""
        try:
            with open(self.signed_file, 'a') as f:
                f.write(json.dumps(signed_obs.to_dict()) + '\n')
        except Exception:
            pass  # Best-effort
    
    def load_pending(self) -> list:
        """Load pending events (for crash recovery)."""
        if not self.pending_file.exists():
            return []
        
        events = []
        try:
            with open(self.pending_file) as f:
                for line in f:
                    if line.strip():
                        event_dict = json.loads(line)
                        events.append(ObservationEvent.from_dict(event_dict))
        except Exception:
            pass  # Best-effort
        
        return events
    
    def clear_pending(self) -> None:
        """Clear pending buffer."""
        try:
            if self.pending_file.exists():
                self.pending_file.unlink()
        except Exception:
            pass


class EvidenceEmitter:
    """
    Async evidence emitter.
    
    Design:
    - Non-blocking queue (drops on overflow)
    - Background signer thread
    - Batch signing (amortized cost)
    - Write-ahead buffer (crash recovery)
    - Graceful shutdown
    """
    
    def __init__(
        self,
        key_manager: Ed25519KeyManager,
        ledger_path: str = ".guardclaw/ledger",
        buffer_dir: Optional[Path] = None,
        signing_interval_seconds: float = 1.0,
        batch_size: int = 100,
        max_queue_size: int = 10000
    ):
        self.key_manager = key_manager
        self.ledger_path = ledger_path
        self.signing_interval = signing_interval_seconds
        self.batch_size = batch_size
        
        # Queue
        self.queue = Queue(maxsize=max_queue_size)
        
        # Buffer
        if buffer_dir is None:
            buffer_dir = Path(ledger_path).parent / "buffer"
        self.buffer = WriteAheadBuffer(buffer_dir)
        
        # Stats
        self.total_emitted = 0
        self.total_signed = 0
        self.total_dropped = 0
        
        # Threading
        self.running = False
        self.signer_thread: Optional[threading.Thread] = None
        
        # Ledger
        self.ledger_dir = Path(ledger_path) / "observations"
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
    
    def start(self) -> None:
        """Start background signer thread."""
        if self.running:
            return
        
        self.running = True
        self.signer_thread = threading.Thread(target=self._signer_loop, daemon=True)
        self.signer_thread.start()
        print(f"🔄 Signer thread started (interval: {self.signing_interval}s)")
    
    def emit(self, event: ObservationEvent) -> None:
        """
        Emit event (non-blocking).
        
        If queue full, drops event and increments counter.
        """
        try:
            # Write to buffer (best-effort)
            self.buffer.append_pending(event)
            
            # Enqueue (non-blocking)
            self.queue.put_nowait(event)
            self.total_emitted += 1
        
        except Full:
            # Queue full, drop event
            self.total_dropped += 1
    
    def _signer_loop(self) -> None:
        """Background signer loop."""
        while self.running:
            try:
                # Collect batch
                batch = []
                deadline = time.time() + self.signing_interval
                
                while time.time() < deadline and len(batch) < self.batch_size:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    
                    try:
                        event = self.queue.get(timeout=min(remaining, 0.1))
                        batch.append(event)
                    except Empty:
                        continue
                
                # Sign batch
                if batch:
                    self._sign_batch(batch)
            
            except Exception as e:
                print(f"⚠️  Signer error: {e}")
                time.sleep(0.1)
    
    def _sign_batch(self, batch: list) -> None:
        """Sign batch of events."""
        emission_time = datetime.now(timezone.utc)
        
        for event in batch:
            try:
                # Calculate accountability lag
                event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                lag_ms = (emission_time - event_time).total_seconds() * 1000
                
                # Sign event
                canonical_bytes = canonical_json_encode(event.to_dict())
                signature = self.key_manager.sign(canonical_bytes)
                
                # Create signed observation
                signed_obs = SignedObservation(
                    event=event,
                    signature=signature,
                    accountability_lag_ms=lag_ms
                )
                
                # Write to buffer
                self.buffer.append_signed(signed_obs)
                
                # Write to ledger
                self._write_to_ledger(signed_obs)
                
                self.total_signed += 1
            
            except Exception as e:
                print(f"⚠️  Signing failed: {e}")
    
    def _write_to_ledger(self, signed_obs: SignedObservation) -> None:
        """Write signed observation to ledger."""
        event_type = signed_obs.event.event_type.value
        ledger_file = self.ledger_dir / f"{event_type}.jsonl"
        
        try:
            with open(ledger_file, 'a') as f:
                f.write(json.dumps(signed_obs.to_dict()) + '\n')
        except Exception as e:
            print(f"⚠️  Ledger write failed: {e}")
    
    def stop(self, timeout: float = 5.0) -> None:
        """Stop emitter gracefully."""
        print(f"🛑 Stopping emitter (queue size: {self.queue.qsize()})...")
        
        self.running = False
        
        # Wait for signer thread
        if self.signer_thread:
            self.signer_thread.join(timeout=timeout)
        
        # Drain remaining queue
        remaining = []
        while not self.queue.empty():
            try:
                event = self.queue.get_nowait()
                remaining.append(event)
            except Empty:
                break
        
        # Sign remaining
        if remaining:
            self._sign_batch(remaining)
        
        print("🛑 Signer thread stopped")
        print(f"✅ Emitter stopped (signed: {self.total_signed}, dropped: {self.total_dropped})")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get emitter statistics."""
        return {
            "running": self.running,
            "total_emitted": self.total_emitted,
            "total_signed": self.total_signed,
            "total_dropped": self.total_dropped,
            "queue_size": self.queue.qsize()
        }


# Global emitter instance
_global_emitter: Optional[EvidenceEmitter] = None


def init_global_emitter(
    key_manager: Ed25519KeyManager,
    ledger_path: str = ".guardclaw/ledger",
    buffer_dir: Optional[Path] = None,
    signing_interval_seconds: float = 1.0,
    batch_size: int = 100,
    max_queue_size: int = 10000
) -> EvidenceEmitter:
    """
    Initialize global emitter instance.
    
    Returns:
        EvidenceEmitter instance
    """
    global _global_emitter
    
    if _global_emitter is not None:
        print("⚠️  Global emitter already exists, stopping old instance...")
        _global_emitter.stop()
    
    _global_emitter = EvidenceEmitter(
        key_manager=key_manager,
        ledger_path=ledger_path,
        buffer_dir=buffer_dir,
        signing_interval_seconds=signing_interval_seconds,
        batch_size=batch_size,
        max_queue_size=max_queue_size
    )
    
    _global_emitter.start()
    
    return _global_emitter


def get_global_emitter() -> Optional[EvidenceEmitter]:
    """Get global emitter instance."""
    return _global_emitter
