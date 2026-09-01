"""
tests/test_storage_worm.py

Validates S3 WORM backend object locking, legal hold headers, and GEFWriter factory method.
"""

from guardclaw.core.storage import GEFWriter, S3WORMBackend


def test_s3_worm_backend_initialization_and_uri():
    class DummyS3:
        def __init__(self):
            self.puts = []

        def get_object(self, Bucket, Key):
            raise Exception("NoSuchKey")

        def put_object(self, **kwargs):
            self.puts.append(kwargs)

    backend = S3WORMBackend(
        bucket="audit-compliance-vault",
        key="agents/banking-agent/ledger.jsonl",
        object_lock_mode="COMPLIANCE",
        legal_hold=True,
    )
    backend._s3 = DummyS3()  # Mock client

    assert "s3-worm://" in backend.uri
    assert "COMPLIANCE" in backend.uri

    writer = GEFWriter(backend)
    writer.write_line('{"test": "worm_entry"}')
    writer.flush()

    assert len(backend._s3.puts) == 1
    put_call = backend._s3.puts[0]
    assert put_call["Bucket"] == "audit-compliance-vault"
    assert put_call["ObjectLockMode"] == "COMPLIANCE"
    assert put_call["ObjectLockLegalHoldStatus"] == "ON"
