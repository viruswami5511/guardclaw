"""
tests/test_kms_provider.py

Validates Cloud KMS, LocalKeyProvider, and MockKMSKeyProvider abstractions.
"""

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.kms import LocalKeyProvider, MockKMSKeyProvider, AWSKMSKeyProvider


def test_local_key_provider_signing():
    km = Ed25519KeyManager.generate()
    provider = LocalKeyProvider(km)
    assert provider.public_key_hex == km.public_key_hex

    data = b"canonical_payload_bytes"
    sig = provider.sign_bytes(data)
    assert sig
    assert Ed25519KeyManager.verify_detached(data, sig, provider.public_key_hex) is True


def test_mock_kms_provider_signing():
    provider = MockKMSKeyProvider("arn:aws:kms:us-east-1:123456789012:key/test-agent-key")
    assert len(provider.public_key_hex) == 64
    assert provider.call_count == 0

    data = b"important_banking_decision"
    sig = provider.sign_bytes(data)
    assert provider.call_count == 1
    assert Ed25519KeyManager.verify_detached(data, sig, provider.public_key_hex) is True


def test_aws_kms_provider_mocked_client():
    class DummyBotoKMS:
        def get_public_key(self, KeyId):
            return {"PublicKey": b"\x01" * 32}

        def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
            return {"Signature": b"\x02" * 64}

    provider = AWSKMSKeyProvider(
        key_id="arn:aws:kms:eu-central-1:123456789012:key/ed25519-hsm",
        boto_client=DummyBotoKMS(),
    )
    assert provider.public_key_hex == ("01" * 32)
    sig = provider.sign_bytes(b"payload")
    assert sig
