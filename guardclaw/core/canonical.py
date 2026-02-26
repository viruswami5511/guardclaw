"""
GuardClaw: Canonical JSON Encoding — RFC 8785 (JCS)

This is the ONLY canonicalization permitted in GuardClaw.
All signing, hashing, and chain computation MUST use this module.

RFC 8785: https://www.rfc-editor.org/rfc/rfc8785
"""

import hashlib

try:
    import jcs as _jcs
except ImportError as exc:
    raise ImportError(
        "GuardClaw requires the 'jcs' package for RFC 8785 compliance.\n"
        "Install with: pip install jcs\n"
        f"Original error: {exc}"
    ) from exc


def canonicalize(obj: dict) -> bytes:
    """
    Encode a dict to RFC 8785 canonical JSON bytes.

    Output is deterministic regardless of key insertion order.
    All values must be JSON-primitive (str, int, float, bool, None, list, dict).
    Do NOT pass datetime objects — convert to .isoformat() strings first.

    Returns:
        UTF-8 encoded canonical JSON bytes, suitable for signing.
    """
    return _jcs.canonicalize(obj)


def canonical_hash(obj: dict) -> str:
    """
    SHA-256 of the RFC 8785 canonical form.

    Used for causal_hash chaining and record binding.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 characters).
    """
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def canonical_json_encode(obj: dict) -> bytes:
    """
    Backward-compatibility alias for canonicalize().

    Existing code importing canonical_json_encode continues to work.
    New code should call canonicalize() directly.
    """
    return canonicalize(obj)
