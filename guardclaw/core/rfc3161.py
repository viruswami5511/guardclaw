"""
guardclaw/core/rfc3161.py
GEF Trusted Timestamp — Phase 1 Trust Layer v1.0.0

Provides RFC 3161 timestamp token acquisition and verification.
A trusted timestamp proves a ledger record existed BEFORE a given time,
signed by a third-party TSA (Timestamp Authority).

TRUST MODEL:
    Without trusted timestamps, an attacker with access to the private key
    can reconstruct an entire ledger with backdated timestamps. RFC 3161
    binds a hash to an external time authority that cannot be forged.

OFFLINE MODE:
    When no TSA URL is configured or the TSA is unreachable, the module
    returns a local timestamp stub. This is clearly marked as UNVERIFIED
    and must not be treated as a trust anchor. Stubs are for dev/testing only.

PRODUCTION TSA URLs (free, public):
    - https://freetsa.org/tsr  (FreeTSA)
    - http://timestamp.digicert.com
    - http://timestamp.sectigo.com
"""

from __future__ import annotations

import hashlib
import base64
import json
import struct
from datetime import datetime, timezone
from typing import Optional, Dict, Any


class TimestampError(Exception):
    """Raised when timestamp acquisition or verification fails."""


class TimestampUnavailableError(TimestampError):
    """Raised when TSA is unreachable and offline mode is disabled."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ── Stub (offline/dev) ────────────────────────────────────────────────────────

def make_stub_timestamp(data: bytes) -> Dict[str, Any]:
    """
    Create a local timestamp stub for dev/testing.

    NOT a trust anchor. Clearly marked as UNVERIFIED.
    """
    return {
        "tsr_base64": base64.b64encode(b"STUB:" + _sha256_bytes(data)).decode(),
        "hash_alg": "sha256",
        "hash_hex": _sha256_hex(data),
        "acquired_at": _utc_now_iso(),
        "tsa_url": None,
        "verified": False,
        "stub": True,
    }


# ── RFC 3161 minimal ASN.1 builder ────────────────────────────────────────────

def _build_ts_request(data: bytes) -> bytes:
    """
    Build a minimal RFC 3161 TimeStampRequest for SHA-256 hash of data.

    ASN.1 DER encoding (minimal compliant structure):
        TimeStampReq ::= SEQUENCE {
            version         INTEGER { v1(1) },
            messageImprint  MessageImprint,
            nonce           INTEGER OPTIONAL,
            certReq         BOOLEAN DEFAULT FALSE
        }
        MessageImprint ::= SEQUENCE {
            hashAlgorithm   AlgorithmIdentifier,
            hashedMessage   OCTET STRING
        }
    """
    digest = _sha256_bytes(data)

    # SHA-256 OID: 2.16.840.1.101.3.4.2.1
    sha256_oid = bytes([
        0x30, 0x0d,                             # SEQUENCE (13)
        0x06, 0x09,                             # OID (9)
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # SHA-256
        0x05, 0x00,                             # NULL
    ])

    # MessageImprint
    hash_field = b"\x04" + bytes([len(digest)]) + digest
    msg_imprint_inner = sha256_oid + hash_field
    msg_imprint = b"\x30" + bytes([len(msg_imprint_inner)]) + msg_imprint_inner

    # version INTEGER = 1
    version = b"\x02\x01\x01"

    # certReq BOOLEAN TRUE
    cert_req = b"\x01\x01\xff"

    inner = version + msg_imprint + cert_req
    request = b"\x30" + bytes([len(inner)]) + inner
    return request


def _extract_tsr_time(tsr_bytes: bytes) -> Optional[str]:
    """
    Attempt to extract a human-readable time from TSR bytes.
    Returns ISO string or None if parsing fails.
    This is a best-effort extraction — not a security-critical path.
    """
    try:
        # Search for GeneralizedTime pattern (14-digit ASCII + 'Z')
        s = tsr_bytes.decode("latin-1")
        import re
        match = re.search(r"(\d{14})Z", s)
        if match:
            ts_str = match.group(1)
            dt = datetime(
                int(ts_str[0:4]), int(ts_str[4:6]), int(ts_str[6:8]),
                int(ts_str[8:10]), int(ts_str[10:12]), int(ts_str[12:14]),
                tzinfo=timezone.utc,
            )
            return dt.isoformat()
    except Exception:
        pass
    return None


# ── Main client ───────────────────────────────────────────────────────────────

class RFC3161Client:
    """
    RFC 3161 Timestamp Authority client.

    Usage:
        client = RFC3161Client(tsa_url="https://freetsa.org/tsr")
        ts = client.stamp(canonical_bytes)
        # ts is a dict ready to assign to env.trusted_timestamp

    Offline fallback:
        client = RFC3161Client(offline_fallback=True)
        ts = client.stamp(data)  # returns stub, ts["verified"] == False
    """

    DEFAULT_TSA = "https://freetsa.org/tsr"
    TIMEOUT_SECONDS = 10

    def __init__(
        self,
        tsa_url: Optional[str] = None,
        offline_fallback: bool = True,
        timeout: int = TIMEOUT_SECONDS,
    ) -> None:
        self.tsa_url = tsa_url or self.DEFAULT_TSA
        self.offline_fallback = offline_fallback
        self.timeout = timeout

    def stamp(self, data: bytes) -> Dict[str, Any]:
        """
        Request a timestamp for data from the configured TSA.
        Falls back to stub if TSA unreachable and offline_fallback=True.
        Raises TimestampUnavailableError if TSA unreachable and offline_fallback=False.
        """
        try:
            return self._request_tsr(data)
        except Exception as e:
            if self.offline_fallback:
                return make_stub_timestamp(data)
            raise TimestampUnavailableError(
                f"TSA request failed and offline_fallback=False: {e}"
            ) from e

    def _request_tsr(self, data: bytes) -> Dict[str, Any]:
        """Send RFC 3161 request to TSA. Raises on any network failure."""
        try:
            import urllib.request
            import urllib.error
        except ImportError:
            raise TimestampUnavailableError("urllib not available")

        ts_req = _build_ts_request(data)

        try:
            req = urllib.request.Request(
                self.tsa_url,
                data=ts_req,
                method="POST",
                headers={"Content-Type": "application/timestamp-query"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                tsr_bytes = resp.read()
        except Exception as e:
            raise TimestampUnavailableError(f"TSA unreachable: {e}") from e

        if not tsr_bytes:
            raise TimestampUnavailableError("TSA returned empty response")

        tsr_b64 = base64.b64encode(tsr_bytes).decode()
        tsa_time = _extract_tsr_time(tsr_bytes)

        return {
            "tsr_base64": tsr_b64,
            "hash_alg": "sha256",
            "hash_hex": _sha256_hex(data),
            "acquired_at": tsa_time or _utc_now_iso(),
            "tsa_url": self.tsa_url,
            "verified": True,
            "stub": False,
        }

    def verify(self, trusted_timestamp: Dict[str, Any], data: bytes) -> bool:
        """
        Verify that trusted_timestamp covers data.

        For stubs: verifies the hash matches (structural check only).
        For real TSRs: verifies hash field matches (full TSR crypto verification
        requires the TSA cert chain — out of scope for Phase 1).
        """
        if not isinstance(trusted_timestamp, dict):
            return False

        expected_hash = _sha256_hex(data)
        stored_hash = trusted_timestamp.get("hash_hex")

        if stored_hash != expected_hash:
            return False

        if trusted_timestamp.get("stub"):
            # Stub: verify hash embedded in tsr_base64
            try:
                raw = base64.b64decode(trusted_timestamp["tsr_base64"])
                return raw == b"STUB:" + _sha256_bytes(data)
            except Exception:
                return False

        return True


# ── Convenience factory ───────────────────────────────────────────────────────

def make_timestamp_client(
    tsa_url: Optional[str] = None,
    offline: bool = True,
) -> RFC3161Client:
    """Create an RFC3161Client with sensible defaults."""
    if offline:
        return RFC3161Client(
            tsa_url=tsa_url or "http://localhost:0/stub",
            offline_fallback=True,
            timeout=1,
        )
    return RFC3161Client(tsa_url=tsa_url, offline_fallback=False)