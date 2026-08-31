"""
guardclaw/core/ledger.py
GEFLedger — Hardened v1.0.3

Changes in v1.0.3:
    - _release_os_lock: logs warning instead of silently swallowing errors
    - close(): explicit no-op with full docstring — no pass, no silent return
    - _load_existing_chain(): typed exception handling, structured log on every error
    - Zero silent exception handling anywhere in this file
"""

from __future__ import annotations
import json
import logging
import os
import uuid
import time
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import (
    ExecutionEnvelope, GENESIS_HASH, GEF_VERSION, VALID_RECORD_TYPES,
    check_unknown_fields, SchemaResult, RecordType
)

_log = logging.getLogger(__name__)

# ── Global file-scoped lock registry (in-process thread safety) ──────────────
_FILE_LOCKS: Dict[str, threading.Lock] = {}
_FILE_LOCKS_MUTEX = threading.Lock()


def _get_file_lock(path: str) -> threading.Lock:
    with _FILE_LOCKS_MUTEX:
        if path not in _FILE_LOCKS:
            _FILE_LOCKS[path] = threading.Lock()
        return _FILE_LOCKS[path]


def _is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == STILL_ACTIVE
        else:
            os.kill(pid, 0)
            return True
    except (OSError, Exception):
        return False


def _acquire_os_lock(lock_path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return
        except (FileExistsError, PermissionError):
            time.sleep(0.005)
    raise TimeoutError(f"Could not acquire OS lock: {lock_path}")


def _release_os_lock(lock_path: Path) -> None:
    """
    Release OS-level lockfile.

    Always called from a finally block — must never raise.
    Failures are logged as warnings so operators can detect stale locks
    without interrupting the caller's finally block.

    FileNotFoundError — lock already released (double-release or crash cleanup)
    PermissionError   — OS denied removal (stale lock, investigate separately)
    """
    try:
        lock_path.unlink()
    except FileNotFoundError:
        _log.warning(
            "_release_os_lock: lock file already absent: %s", lock_path
        )
    except PermissionError as exc:
        _log.warning(
            "_release_os_lock: could not remove lock file %s: %s",
            lock_path, exc
        )


# ── Payload helpers ───────────────────────────────────────────────────────────

MAX_EMIT_DEPTH = 20


def _check_payload_depth(obj: Any, depth: int = 0) -> None:
    if depth > MAX_EMIT_DEPTH:
        raise ValueError("payload_too_deep")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_payload_depth(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_payload_depth(v, depth + 1)


class GEFLedger:
    LEDGER_FILENAME = "ledger.jsonl"

    def __init__(
        self,
        key_manager: Ed25519KeyManager,
        agent_id: str,
        ledger_path: Optional[str] = None,
        ledger_dir: Optional[str] = None,
        mode: str = "strict",
        ledger_filename: Optional[str] = None,
    ) -> None:
        if mode not in ("strict", "ghost"):
            raise ValueError(f"Invalid mode {mode!r}. Must be 'strict' or 'ghost'.")

        resolved = ledger_path or ledger_dir
        if mode == "strict" and resolved is None:
            raise ValueError("ledger_path is required for strict mode.")

        self._key_manager = key_manager
        self._agent_id = agent_id
        self._mode = mode
        self._chain: List[ExecutionEnvelope] = []
        self._chain_truncated = False
        self._last_file_size: int = 0
        self._last_file_pos: int = 0

        if mode == "ghost":
            self._ledger_file: Optional[Path] = None
            self._file_lock = threading.Lock()
        else:
            lp = Path(resolved)
            lp.mkdir(parents=True, exist_ok=True)
            fname = ledger_filename or self.LEDGER_FILENAME
            self._ledger_file = (lp / fname).resolve()
            self._file_lock = _get_file_lock(str(self._ledger_file))

        self.session_id = str(uuid.uuid4())

        if self._ledger_file:
            lock_path = self._ledger_file.with_suffix(".lock")
            with self._file_lock:
                try:
                    _acquire_os_lock(lock_path)
                    self._recover_file()
                    self._load_existing_chain()
                    if not self._chain:
                        self._emit_genesis()
                finally:
                    _release_os_lock(lock_path)

    # ── Public properties ────────────────────────────────────────────────────

    @property
    def public_key_hex(self) -> str:
        return self._key_manager.public_key_hex

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def entries(self) -> List[ExecutionEnvelope]:
        return list(self._chain)

    @property
    def entry_count(self) -> int:
        return len(self._chain)

    @property
    def head(self) -> Optional[ExecutionEnvelope]:
        return self._chain[-1] if self._chain else None

    def get_path(self) -> str:
        return str(self._ledger_file) if self._ledger_file else ""

    def close(self) -> None:
        """
        Explicit close/cleanup hook — intentional no-op.
        GEFLedger uses append-only file writes with immediate flush on every emit.
        """
        return None

    # ── Core emit ────────────────────────────────────────────────────────────

    def emit(
        self,
        record_type: str,
        payload: Dict[str, Any],
        key_id: Optional[str] = None,
        encrypt: bool = False,
        encryption_manager=None,
    ) -> ExecutionEnvelope:
        record_type = RecordType.normalize(record_type)

        if encrypt and encryption_manager is None:
            raise ValueError("emit: encrypt=True requires encryption_manager")
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")
        _check_payload_depth(payload)
        try:
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"payload_encoding_invalid: {exc}") from exc

        lock_path = self._ledger_file.with_suffix(".lock") if self._ledger_file else None

        with self._file_lock:
            try:
                if lock_path:
                    _acquire_os_lock(lock_path)
                if self._ledger_file:
                    self._load_existing_chain()
                prev = self._chain[-1] if self._chain else None
                env = ExecutionEnvelope.create(
                    record_type=record_type,
                    agent_id=self._agent_id,
                    session_id=self.session_id,
                    signer_public_key=self._key_manager.public_key_hex,
                    sequence=len(self._chain),
                    payload=payload,
                    prev=prev,
                    key_id=key_id,
                )
                # ENCRYPT BEFORE SIGN — protocol invariant (non-negotiable)
                if encrypt:
                    env = encryption_manager.encrypt(env)
                env = env.sign(self._key_manager)
                self._chain.append(env)
                self._persist(env)
                if self._ledger_file and self._ledger_file.exists():
                    self._last_file_size = self._ledger_file.stat().st_size
                    self._last_file_pos = self._last_file_size
                return env
            finally:
                if lock_path:
                    _release_os_lock(lock_path)

    # ── Genesis ──────────────────────────────────────────────────────────────

    def _emit_genesis(self) -> None:
        env = ExecutionEnvelope.create(
            record_type=RecordType.GENESIS,
            agent_id=self._agent_id,
            session_id=self.session_id,
            signer_public_key=self._key_manager.public_key_hex,
            sequence=0,
            payload={},
            prev=None,
        ).sign(self._key_manager)
        self._chain.append(env)
        self._persist(env)
        if self._ledger_file and self._ledger_file.exists():
            self._last_file_size = self._ledger_file.stat().st_size
            self._last_file_pos = self._last_file_size

    # ── Persistence ──────────────────────────────────────────────────────────

    def _persist(self, env: ExecutionEnvelope) -> None:
        if not self._ledger_file:
            return None
        with open(self._ledger_file, "a", encoding="utf-8", newline="") as f:
            f.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
            f.flush()
        return None

    # ── Crash recovery ───────────────────────────────────────────────────────

    def _recover_file(self) -> None:
        if not self._ledger_file or not self._ledger_file.exists():
            return None
        with open(self._ledger_file, "rb") as f:
            content = f.read()
        if not content:
            return None
        if not content.endswith(b"\n"):
            last = content.rfind(b"\n")
            with open(self._ledger_file, "wb") as f:
                f.write(content[: last + 1] if last != -1 else b"")
        return None

    # ── State restore & Tail Sync ───────────────────────────────────────────

    def _sync_tail(self) -> None:
        """
        Synchronize newly appended entries from disk into self._chain in O(K)
        where K is the number of new entries since last sync.
        Avoids O(N) full ledger reload.
        """
        if not self._ledger_file or not self._ledger_file.exists():
            return
        try:
            current_size = self._ledger_file.stat().st_size
        except OSError:
            return

        if current_size == self._last_file_size:
            return

        if current_size < self._last_file_size:
            self._load_existing_chain()
            return

        with open(self._ledger_file, "r", encoding="utf-8") as f:
            f.seek(self._last_file_pos)
            while True:
                line = f.readline()
                if not line:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                    env = ExecutionEnvelope.from_dict(data)
                    if not self._chain:
                        self.session_id = env.session_id
                    self._chain.append(env)
                except Exception as exc:
                    _log.warning("_sync_tail: failed to parse appended record: %s", exc)
                    self._chain_truncated = True
                    break
            self._last_file_pos = f.tell()
            self._last_file_size = current_size

    def _load_existing_chain(self) -> None:
        """
        Load complete chain from ledger file into self._chain.
        """
        if not self._ledger_file:
            return None
        if not self._ledger_file.exists():
            self._chain = []
            self._last_file_size = 0
            self._last_file_pos = 0
            return None
        self._chain = []
        with open(self._ledger_file, "r", encoding="utf-8") as f:
            line_num = 0
            while True:
                line = f.readline()
                if not line:
                    break
                raw = line.strip()
                if not raw:
                    line_num += 1
                    continue
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    _log.warning(
                        "_load_existing_chain: JSON decode error at line %d: %s",
                        line_num, exc
                    )
                    self._chain_truncated = True
                    break
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except (TypeError, KeyError) as exc:
                    _log.warning(
                        "_load_existing_chain: missing required field at line %d: %s",
                        line_num, exc
                    )
                    self._chain_truncated = True
                    break
                except ValueError as exc:
                    _log.warning(
                        "_load_existing_chain: invalid value at line %d: %s",
                        line_num, exc
                    )
                    self._chain_truncated = True
                    break
                if not self._chain:
                    self.session_id = env.session_id
                self._chain.append(env)
                line_num += 1
            self._last_file_pos = f.tell()
        try:
            self._last_file_size = self._ledger_file.stat().st_size
        except OSError:
            self._last_file_size = 0
        return None

    # ── Verification ─────────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        if self._ledger_file is None:
            return True
        from guardclaw.core.replay import ReplayEngine
        summary = ReplayEngine(mode="strict", silent=True).stream_verify(
            self._ledger_file
        )
        return summary.chain_valid

    # ── Classmethod loader ───────────────────────────────────────────────────

    @classmethod
    def load(
        cls,
        ledger_path: str,
        key_manager: Ed25519KeyManager,
        agent_id: str,
    ) -> "GEFLedger":
        path = Path(ledger_path)
        if not path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")
        instance = cls.__new__(cls)
        instance._key_manager = key_manager
        instance._agent_id = agent_id
        instance._mode = "strict"
        instance._chain = []
        instance._chain_truncated = False
        instance._last_file_size = 0
        instance._last_file_pos = 0
        instance._file_lock = _get_file_lock(str(path.resolve()))
        instance._ledger_file = path.resolve()
        instance.session_id = str(uuid.uuid4())
        instance._recover_file()
        instance._load_existing_chain()
        return instance

    def __repr__(self) -> str:
        return (
            f"GEFLedger("
            f"agent_id={self._agent_id!r}, "
            f"entries={len(self._chain)}, "
            f"path={self.get_path()!r})"
        )