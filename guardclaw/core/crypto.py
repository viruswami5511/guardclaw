"""
GuardClaw Phase 1: Cryptography (MINIMAL STUB)

This is a reference implementation for Phase 5 testing.
Production systems should use hardened crypto libraries.
"""

import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


class Ed25519KeyManager:
    """
    Ed25519 key manager (stub implementation).
    
    WARNING: This is a minimal stub for Phase 5 testing.
    """
    
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls) -> "Ed25519KeyManager":
        """Generate new Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key)
    
    @classmethod
    def load_keypair(cls, private_key_path: str) -> "Ed25519KeyManager":
        """Load private key from file."""
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return cls(private_key)
    
    @classmethod
    def from_public_key_hex(cls, public_key_hex: str) -> "Ed25519KeyManager":
        """Load public key from hex string (verification only)."""
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Create dummy manager (no private key)
        manager = cls.__new__(cls)
        manager._private_key = None
        manager._public_key = public_key
        return manager
    
    def save_keypair(self, private_key_path: str, public_key_path: str) -> None:
        """Save key pair to files."""
        # CREATE DIRECTORIES IF THEY DON'T EXIST
        private_dir = os.path.dirname(private_key_path)
        if private_dir:
            os.makedirs(private_dir, exist_ok=True)
        
        public_dir = os.path.dirname(public_key_path)
        if public_dir:
            os.makedirs(public_dir, exist_ok=True)
        
        # Save private key
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
    
    def sign(self, data: bytes) -> str:
        """Sign data, return hex-encoded signature."""
        signature = self._private_key.sign(data)
        return signature.hex()
    
    def verify(self, signature: str, data: bytes) -> bool:
        """Verify signature."""
        try:
            signature_bytes = bytes.fromhex(signature)
            self._public_key.verify(signature_bytes, data)
            return True
        except Exception:
            return False
    
    def public_key_hex(self) -> str:
        """Get public key as hex string."""
        public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()


def canonical_json_encode(data: dict) -> bytes:
    """
    Canonical JSON encoding.
    
    Ensures deterministic serialization for signing.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    ).encode('utf-8')


def canonical_hash(data: dict) -> str:
    """
    Compute canonical hash of dictionary.
    
    Returns hex-encoded SHA-256 hash.
    """
    canonical_bytes = canonical_json_encode(data)
    return hashlib.sha256(canonical_bytes).hexdigest()


def hash_sha256(data: bytes) -> str:
    """SHA-256 hash, return hex string."""
    return hashlib.sha256(data).hexdigest()
