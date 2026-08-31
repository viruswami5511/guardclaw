"""
guardclaw/core/canonical.py
Canonical JSON Encoding for all GEF signing surfaces.

This is the ONLY canonicalization permitted in GuardClaw.
All signing, hashing, and chain computation MUST use this module.

Rule: ONE implementation. No other file defines canonical_json_encode.
No JCS. No external dependency. Pure stdlib.
"""

from __future__ import annotations
import hashlib
import json
from typing import Any


def canonical_json_encode(obj: Any) -> bytes:
    """
    Encode to canonical JSON bytes.

    Rules:
        - sort_keys=True        — deterministic field order
        - separators=(",",":")  — no whitespace
        - ensure_ascii=False    — UTF-8 passthrough
        - Returns UTF-8 encoded bytes

    This is the ONLY encoder used for signing, hashing, and AAD.
    Never use jcs.canonicalize() or any other encoder.
    All values must be JSON-serializable (str, int, float, bool, None, list, dict).
    Convert datetime to .isoformat() strings before passing.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# Keep canonicalize as an alias so any existing import of canonicalize() still works
canonicalize = canonical_json_encode


def canonical_hash(obj: Any) -> str:
    """
    SHA-256 of the canonical JSON form.

    Used for causal_hash chaining and record binding.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 characters).
    """
    return hashlib.sha256(canonical_json_encode(obj)).hexdigest()