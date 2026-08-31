"""
tests/test_storage.py
GEFWriter + LocalBackend — full test suite (no cloud creds required)
"""
import pytest
import json
from pathlib import Path
from guardclaw.core.storage import GEFWriter, LocalBackend, StorageError

LINE_A = '{"record_id":"gef-001","sequence":0}'
LINE_B = '{"record_id":"gef-002","sequence":1}'


def test_local_write_and_read(tmp_path):
    path = tmp_path / "ledger.jsonl"
    with GEFWriter.local(path) as w:
        w.write_line(LINE_A)
        w.write_line(LINE_B)
    lines = GEFWriter.local(path).read_all()
    assert lines[0] == LINE_A
    assert lines[1] == LINE_B

def test_local_append_across_instances(tmp_path):
    path = tmp_path / "ledger.jsonl"
    with GEFWriter.local(path) as w:
        w.write_line(LINE_A)
    with GEFWriter.local(path) as w:
        w.write_line(LINE_B)
    lines = GEFWriter.local(path).read_all()
    assert len(lines) == 2

def test_write_after_close_raises(tmp_path):
    path = tmp_path / "ledger.jsonl"
    w = GEFWriter.local(path)
    w.close()
    with pytest.raises(StorageError):
        w.write_line(LINE_A)

def test_write_envelope(tmp_path):
    path = tmp_path / "ledger.jsonl"
    d = {"record_id": "gef-001", "sequence": 0}
    with GEFWriter.local(path) as w:
        w.write_envelope(d)
    lines = GEFWriter.local(path).read_all()
    assert json.loads(lines[0]) == d

def test_context_manager_closes(tmp_path):
    path = tmp_path / "ledger.jsonl"
    with GEFWriter.local(path) as w:
        w.write_line(LINE_A)
    assert w.is_closed

def test_flush(tmp_path):
    path = tmp_path / "ledger.jsonl"
    w = GEFWriter.local(path)
    w.write_line(LINE_A)
    w.flush()
    lines = GEFWriter.local(path).read_all()
    assert len(lines) == 1
    w.close()

def test_uri(tmp_path):
    path = tmp_path / "ledger.jsonl"
    w = GEFWriter.local(path)
    assert str(path) in w.uri
    w.close()

def test_read_all_empty(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.touch()
    w = GEFWriter.local(path)
    assert w.read_all() == []
    w.close()

def test_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "ledger.jsonl"
    with GEFWriter.local(path) as w:
        w.write_line(LINE_A)
    assert path.exists()

def test_repr(tmp_path):
    path = tmp_path / "ledger.jsonl"
    w = GEFWriter.local(path)
    assert "GEFWriter" in repr(w)
    assert "closed=False" in repr(w)
    w.close()
    assert "closed=True" in repr(w)