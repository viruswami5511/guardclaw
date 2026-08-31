"""
tests/test_rfc3161.py
RFC3161Client — offline/stub tests (no network required)
"""
import pytest
import base64
from guardclaw.core.rfc3161 import (
    RFC3161Client, make_stub_timestamp,
    TimestampUnavailableError, _sha256_hex, _sha256_bytes,
)

DATA = b"guardclaw test canonical bytes"


def test_stub_timestamp_structure():
    ts = make_stub_timestamp(DATA)
    assert "tsr_base64" in ts
    assert ts["hash_alg"] == "sha256"
    assert ts["hash_hex"] == _sha256_hex(DATA)
    assert ts["verified"] is False
    assert ts["stub"] is True
    assert ts["tsa_url"] is None

def test_stub_timestamp_verify_ok():
    client = RFC3161Client(offline_fallback=True)
    ts = make_stub_timestamp(DATA)
    assert client.verify(ts, DATA)

def test_stub_timestamp_verify_wrong_data():
    client = RFC3161Client(offline_fallback=True)
    ts = make_stub_timestamp(DATA)
    assert not client.verify(ts, b"different data")

def test_offline_client_returns_stub_on_bad_url():
    client = RFC3161Client(
        tsa_url="http://localhost:19999/nonexistent",
        offline_fallback=True,
        timeout=1,
    )
    ts = client.stamp(DATA)
    assert ts["stub"] is True
    assert ts["verified"] is False

def test_offline_false_raises_on_bad_url():
    client = RFC3161Client(
        tsa_url="http://localhost:19999/nonexistent",
        offline_fallback=False,
        timeout=1,
    )
    with pytest.raises(TimestampUnavailableError):
        client.stamp(DATA)

def test_verify_wrong_hash():
    client = RFC3161Client(offline_fallback=True)
    ts = make_stub_timestamp(DATA)
    ts["hash_hex"] = "0" * 64  # tampered
    assert not client.verify(ts, DATA)

def test_verify_not_dict():
    client = RFC3161Client(offline_fallback=True)
    assert not client.verify(None, DATA)
    assert not client.verify("string", DATA)

def test_make_timestamp_client():
    from guardclaw.core.rfc3161 import make_timestamp_client
    client = make_timestamp_client(offline=True)
    ts = client.stamp(DATA)
    assert ts["stub"] is True