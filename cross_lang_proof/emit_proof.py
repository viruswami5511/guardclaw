"""
cross_lang_proof/emit_proof.py

GEF Cross-Language Proof — Python Emitter
==========================================

Emits ONE canonical GEF envelope using a deterministic key seed,
then dumps a complete proof bundle to proof_bundle.json.

The bundle contains EVERY intermediate value:
    - signing_dict        (the dict that gets signed)
    - canonical_bytes_hex (signing_dict after JCS, as hex)
    - canonical_bytes_b64 (same, as base64 for readability)
    - chain_dict          (the dict that gets hashed for causal_hash)
    - chain_bytes_hex     (chain_dict after JCS, as hex)
    - causal_hash_of_this (SHA-256 of chain_bytes — what NEXT entry uses)
    - public_key_hex      (raw Ed25519 public key, 32 bytes, 64 hex chars)
    - signature_b64url    (base64url, no padding — as stored in ledger)
    - signature_hex       (same signature as hex, for Go verification)
    - envelope_json       (the full envelope as it appears in a JSONL ledger)

Go reads proof_bundle.json and independently recomputes:
    1. canonical_bytes from signing_dict using Go's JCS
    2. causal_hash_of_this from chain_dict using Go's SHA-256
    3. verifies signature using Go's crypto/ed25519

If all three match — GEF is a cross-language protocol.

Usage:
    cd cross_lang_proof
    python emit_proof.py
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

# Add project root to path so we can import guardclaw
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import ExecutionEnvelope, RecordType


# ── Deterministic key seed ────────────────────────────────────────────────────
# FIXED 32-byte seed → deterministic key → reproducible proof bundle.
# This is NOT a security key. It exists solely to make the proof reproducible
# across runs and across machines.
PROOF_SEED = bytes.fromhex(
    "deadbeefdeadbeefdeadbeefdeadbeef"
    "cafebabecafebabecafebabecafebabe"
)


def main():
    out_path = Path(__file__).parent / "proof_bundle.json"

    # ── Key ──────────────────────────────────────────────────
    key = Ed25519KeyManager.from_private_bytes(PROOF_SEED)
    print(f"Public key (hex) : {key.public_key_hex}")

    # ── Envelope ─────────────────────────────────────────────
    # Fixed payload — deterministic, no timestamps from gef_timestamp()
    # We manually set timestamp and nonce to fixed values so the bundle
    # is reproducible across machines.
    env = ExecutionEnvelope(
        gef_version=       "1.0",
        record_id=         "gef-cross-lang-proof-v1",
        record_type=       "execution",
        agent_id=          "cross-lang-proof-agent",
        signer_public_key= key.public_key_hex,
        sequence=          0,
        nonce=             "abcdef1234567890abcdef1234567890",
        timestamp=         "2026-02-25T00:00:00.000Z",
        causal_hash=       "0" * 64,
        payload=           {"proof": "cross-language", "version": "1.0"},
        signature=         None,
    )

    # ── Sign ─────────────────────────────────────────────────
    env.sign(key)

    # ── Intermediate values for Go verification ──────────────
    signing_dict      = env.to_signing_dict()
    canonical_bytes   = canonical_json_encode(signing_dict)

    chain_dict        = env.to_chain_dict()
    chain_bytes       = canonical_json_encode(chain_dict)
    causal_hash_next  = hashlib.sha256(chain_bytes).hexdigest()

    # Decode signature from base64url (no padding) → raw 64 bytes → hex
    sig_b64url        = env.signature
    padding           = 4 - len(sig_b64url) % 4
    sig_raw           = base64.urlsafe_b64decode(sig_b64url + "=" * (padding % 4))
    sig_hex           = sig_raw.hex()

    # ── Proof bundle ─────────────────────────────────────────
    bundle = {
        "_description": (
            "GEF Cross-Language Proof Bundle. "
            "Python emitter → Go verifier. "
            "All values must match independently computed Go output."
        ),
        "gef_version":             "1.0",
        "public_key_hex":          key.public_key_hex,
        "signing_dict":            signing_dict,
        "canonical_bytes_hex":     canonical_bytes.hex(),
        "canonical_bytes_b64":     base64.b64encode(canonical_bytes).decode(),
        "chain_dict":              chain_dict,
        "chain_bytes_hex":         chain_bytes.hex(),
        "causal_hash_of_this":     causal_hash_next,
        "signature_b64url":        sig_b64url,
        "signature_hex":           sig_hex,
        "envelope_json":           json.dumps(env.to_dict()),
        "expected_results": {
            "canonical_bytes_match": True,
            "chain_hash_match":      True,
            "signature_valid":       True,
        }
    }

    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"Proof bundle written to: {out_path}")
    print()
    print("Expected Go verification:")
    print(f"  canonical_bytes_hex : {canonical_bytes.hex()[:64]}...")
    print(f"  causal_hash_of_this : {causal_hash_next}")
    print(f"  signature_b64url    : {sig_b64url[:32]}...")
    print(f"  signature_valid     : True")
    print()
    print("Now run: go run verify_proof.go")


if __name__ == "__main__":
    main()
