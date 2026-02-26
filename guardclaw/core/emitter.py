"""
guardclaw/core/emitter.py

GEF Ledger — v0.2.0
Aligned to: GEF-SPEC-v1.0

GEF Contract — emit() MUST, in this exact order:
  1. Acquire lock
  2. Call ExecutionEnvelope.create(record_type, agent_id, signer_public_key,
                                   sequence, payload, prev=last_envelope)
  3. Call envelope.sign(key_manager)
  4. Assert chain invariants  — causal_hash, sequence
  5. Append to JSONL ledger   — atomic OS write
  6. Advance internal state   — only after confirmed write
  7. Return signed envelope   — signature is GUARANTEED non-empty

Signature MUST exist before emit() returns.
No background threads. No batching. No deferred signing.
No SCHEMA_VERSION. No ledger_id field. No monotonic nonce.
Nonce is 32-char random hex — generated inside ExecutionEnvelope.create().

Drift check — this file must NOT:
  - Import SCHEMA_VERSION
  - Import gef_timestamp from models (it lives in core/time.py)
  - Construct ExecutionEnvelope() directly (use .create() only)
  - Compute causal_hash outside models.py
  - Compute canonical bytes outside canonical.py
"""

import json
import threading
import warnings
from pathlib import Path
from typing import Any, Dict, Optional

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import (
    ExecutionEnvelope,
    GEF_VERSION,
    GENESIS_HASH,
    RecordType,
)


class GEFLedger:
    """
    GEF-compliant synchronous evidence ledger.

    Maintains per-ledger chain state:
        _sequence        — monotonically increasing integer (0, 1, 2, ...)
        _last_envelope   — the last ExecutionEnvelope appended (or None)

    Nonce is generated inside ExecutionEnvelope.create() as 32-char random hex.
    This class never touches nonce directly.

    Thread-safe via internal lock (single-process only).
    State survives process restart by replaying the ledger file on __init__.
    """

    def __init__(
        self,
        key_manager:  Ed25519KeyManager,
        agent_id:     str,
        ledger_path:  str = ".guardclaw/ledger",
    ) -> None:
        self.key_manager = key_manager
        self.agent_id    = agent_id

        self._lock:          threading.Lock              = threading.Lock()
        self._sequence:      int                         = 0
        self._last_envelope: Optional[ExecutionEnvelope] = None

        self._ledger_dir  = Path(ledger_path)
        self._ledger_dir.mkdir(parents=True, exist_ok=True)
        self._ledger_file = self._ledger_dir / "ledger.jsonl"

        self._restore_state()

    # ── Public API ────────────────────────────────────────────

    def emit(
        self,
        record_type: str,
        payload:     Dict[str, Any],
        agent_id:    Optional[str] = None,
    ) -> ExecutionEnvelope:
        """
        Emit one GEF-compliant signed ExecutionEnvelope.

        Signs synchronously. Signature is guaranteed non-empty on return.
        Raises RuntimeError on any invariant violation or write failure.
        Caller must treat a raised exception as a hard failure.

        Args:
            record_type: Must be a RecordType constant.
            payload:     Record content. Must be JSON-serializable dict.
            agent_id:    Override ledger's default agent_id for this record.

        Returns:
            Fully signed ExecutionEnvelope.
        """
        with self._lock:
            # Step 1 — Create unsigned envelope via THE ONLY constructor
            # ExecutionEnvelope.create() handles:
            #   - record_type validation
            #   - nonce generation (32-char random hex)
            #   - causal_hash computation from prev
            #   - gef_version assignment
            envelope = ExecutionEnvelope.create(
                record_type=       record_type,
                agent_id=          agent_id or self.agent_id,
                signer_public_key= self.key_manager.public_key_hex,
                sequence=          self._sequence,
                payload=           payload,
                prev=              self._last_envelope,
            )

            # Step 2 — Sign (mutates in place, returns self)
            envelope.sign(self.key_manager)

            # Step 3 — Assert chain invariants before any disk write
            self._assert_chain_invariants(envelope)

            # Step 4 — Write to ledger — must succeed before state advances
            self._append_to_ledger(envelope)

            # Step 5 — Advance state only after confirmed write
            self._sequence      += 1
            self._last_envelope  = envelope

            return envelope

    def verify_chain(self) -> bool:
        """
        Verify full ledger chain integrity from genesis.

        For each envelope verifies:
            - Signature valid against embedded signer_public_key
            - causal_hash matches expected value from prev
            - sequence is strictly sequential from 0

        Returns True if entire chain is intact. False if any violation found.
        All verification delegates to ExecutionEnvelope methods — no local logic.
        """
        if not self._ledger_file.exists():
            return True

        try:
            envelopes = []
            with open(self._ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    env = ExecutionEnvelope.from_dict(json.loads(line))
                    envelopes.append(env)

            for i, env in enumerate(envelopes):
                prev = envelopes[i - 1] if i > 0 else None

                if not env.verify_sequence(i):
                    return False
                if not env.verify_chain(prev):
                    return False
                if not env.verify_signature():
                    return False

            return True

        except Exception:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Return current ledger state snapshot."""
        return {
            "agent_id":          self.agent_id,
            "next_sequence":     self._sequence,
            "last_record_id":    (
                self._last_envelope.record_id
                if self._last_envelope else None
            ),
            "last_causal_hash":  (
                self._last_envelope.causal_hash
                if self._last_envelope else GENESIS_HASH
            ),
            "ledger_file":       str(self._ledger_file),
            "gef_version":       GEF_VERSION,
        }

    # ── Internal ──────────────────────────────────────────────

    def _restore_state(self) -> None:
        """
        Restore sequence and last_envelope from an existing ledger.
        Called once at construction. Safe on empty or missing file.
        If the last line is corrupted, state stays at genesis defaults
        and a RuntimeWarning is issued.
        """
        if not self._ledger_file.exists():
            return

        last_line = None
        try:
            with open(self._ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
        except Exception:
            return

        if not last_line:
            return

        try:
            data = json.loads(last_line)
            env  = ExecutionEnvelope.from_dict(data)

            # Validate schema before trusting restored state
            schema = env.validate_schema()
            if not schema:
                raise ValueError(
                    f"Schema violation in last ledger line: {schema.errors}"
                )

            self._sequence      = env.sequence + 1
            self._last_envelope = env

        except Exception as exc:
            warnings.warn(
                f"GEFLedger: could not restore state from {self._ledger_file}: {exc}. "
                "Last line may be corrupted. Call verify_chain() before emitting.",
                RuntimeWarning,
                stacklevel=3,
            )

    def _assert_chain_invariants(self, envelope: ExecutionEnvelope) -> None:
        """
        Raise RuntimeError if the envelope violates any chain invariant.

        Checks:
            1. sequence == self._sequence
            2. causal_hash == expected value from self._last_envelope

        Uses envelope's own verify_chain() and verify_sequence() —
        no local hash or sequence logic here.
        """
        if not envelope.verify_sequence(self._sequence):
            raise RuntimeError(
                f"Chain invariant violated — sequence mismatch: "
                f"expected={self._sequence}, got={envelope.sequence}"
            )

        if not envelope.verify_chain(self._last_envelope):
            expected = envelope.expected_causal_hash_from(self._last_envelope)
            raise RuntimeError(
                f"Chain invariant violated — causal_hash mismatch: "
                f"expected=...{expected[-12:]}, "
                f"got=...{envelope.causal_hash[-12:]}"
            )

    def _append_to_ledger(self, envelope: ExecutionEnvelope) -> None:
        """
        Append one signed envelope as a newline-terminated JSON line.
        Uses envelope.to_dict() — the only serialization path.
        Raises RuntimeError on any I/O failure.
        State MUST NOT advance if this raises.
        """
        try:
            with open(self._ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(envelope.to_dict()) + "\n")
        except Exception as exc:
            raise RuntimeError(
                f"GEFLedger: ledger write failed — {exc}"
            ) from exc


# ── Global Instance Helpers ───────────────────────────────────

_global_ledger: Optional[GEFLedger] = None


def init_global_ledger(
    key_manager:  Ed25519KeyManager,
    agent_id:     str,
    ledger_path:  str = ".guardclaw/ledger",
) -> GEFLedger:
    """
    Initialize and return the process-wide GEFLedger instance.
    Safe to call multiple times — replaces the previous in-memory instance.
    Previous ledger files are preserved on disk.
    """
    global _global_ledger
    _global_ledger = GEFLedger(
        key_manager= key_manager,
        agent_id=    agent_id,
        ledger_path= ledger_path,
    )
    return _global_ledger


def get_global_ledger() -> Optional[GEFLedger]:
    """Return the global GEFLedger, or None if not yet initialized."""
    return _global_ledger


# ── Deprecated Shims ─────────────────────────────────────────
# Removed in v0.3.0. Raises DeprecationWarning immediately.

class EvidenceEmitter:
    """
    DEPRECATED — violates GEF Section 7.1.

    EvidenceEmitter used deferred batch signing. Signatures did not exist
    when emit() returned — a direct violation of the GEF signing contract.

    Migration: use GEFLedger instead.
    Will be removed in v0.3.0.
    """
    def __init__(self, *args, **kwargs):
        warnings.warn(
            "EvidenceEmitter is deprecated and violates GEF Section 7.1 "
            "(signature must exist before emit() returns). "
            "Use guardclaw.core.emitter.GEFLedger instead.",
            DeprecationWarning,
            stacklevel=2,
        )


def init_global_emitter(*args, **kwargs) -> None:
    """DEPRECATED — use init_global_ledger() instead."""
    warnings.warn(
        "init_global_emitter() is deprecated. "
        "Use guardclaw.core.emitter.init_global_ledger() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
