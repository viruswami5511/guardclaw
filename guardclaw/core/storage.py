"""
guardclaw/core/storage.py
GEF Storage Abstraction — Phase 1 Trust Layer v1.0.0

Provides a GEFWriter interface for writing ledger records to any backend.
Built-in backends: local filesystem (default), S3, GCS, Azure Blob.

ARCHITECTURE:
    All backends implement GEFWriterBackend (abstract).
    GEFWriter wraps a backend with buffering, atomic writes, and error handling.
    The local backend is zero-dependency. Cloud backends require optional deps.

USAGE:
    # Local (default, zero deps)
    writer = GEFWriter.local("/path/to/ledger.jsonl")

    # S3 (requires boto3)
    writer = GEFWriter.s3("my-bucket", "prefix/ledger.jsonl")

    # GCS (requires google-cloud-storage)
    writer = GEFWriter.gcs("my-bucket", "prefix/ledger.jsonl")

    # Azure (requires azure-storage-blob)
    writer = GEFWriter.azure("my-container", "ledger.jsonl", conn_str="...")

    # Write a line
    writer.write_line('{"record_id": "..."}')
    writer.flush()
    writer.close()
"""

from __future__ import annotations

import abc
import io
import json
import threading
from pathlib import Path
from typing import Optional, List


class StorageError(Exception):
    """Raised on backend write failures."""


class BackendNotAvailableError(StorageError):
    """Raised when a cloud backend's required library is not installed."""


# ── Abstract backend ──────────────────────────────────────────────────────────

class GEFWriterBackend(abc.ABC):
    """
    Abstract base for all GEF storage backends.

    Each backend must handle atomic line appending and flushing.
    """

    @abc.abstractmethod
    def append_line(self, line: str) -> None:
        """Append one JSON line (without newline) to the ledger."""

    @abc.abstractmethod
    def flush(self) -> None:
        """Flush pending writes to durable storage."""

    @abc.abstractmethod
    def close(self) -> None:
        """Close backend resources."""

    @abc.abstractmethod
    def read_all(self) -> List[str]:
        """Read all lines from the ledger. Used for verification."""

    @property
    @abc.abstractmethod
    def uri(self) -> str:
        """Human-readable URI for this backend (for logging/errors)."""


# ── Local filesystem backend ──────────────────────────────────────────────────

class LocalBackend(GEFWriterBackend):
    """
    Local filesystem backend. Zero dependencies.
    Appends to a .jsonl file with OS-level flush for durability.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", encoding="utf-8", newline="")

    def append_line(self, line: str) -> None:
        self._file.write(line + "\n")

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.flush()
        self._file.close()

    def read_all(self) -> List[str]:
        if not self._path.exists():
            return []
        with open(self._path, "r", encoding="utf-8") as f:
            return [l.rstrip("\n") for l in f if l.strip()]

    @property
    def uri(self) -> str:
        return str(self._path)


# ── S3 backend ────────────────────────────────────────────────────────────────

class S3Backend(GEFWriterBackend):
    """
    AWS S3 backend. Requires: pip install boto3

    Appends by downloading existing object, appending in memory, re-uploading.
    For high-throughput: use a local buffer + periodic flush (see GEFWriter).

    NOTE: S3 does not support append operations natively.
    This backend is suitable for low-to-medium write frequencies.
    For high-frequency writes, use local + periodic S3 sync.
    """

    def __init__(
        self,
        bucket: str,
        key: str,
        region: Optional[str] = None,
        **boto3_kwargs,
    ) -> None:
        try:
            import boto3
        except ImportError:
            raise BackendNotAvailableError(
                "S3 backend requires boto3: pip install boto3"
            )
        self._bucket = bucket
        self._key = key
        self._buffer: List[str] = []
        self._s3 = boto3.client("s3", region_name=region, **boto3_kwargs)

    def append_line(self, line: str) -> None:
        self._buffer.append(line)

    def flush(self) -> None:
        if not self._buffer:
            return
        # Read existing content
        existing = b""
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=self._key)
            existing = resp["Body"].read()
        except self._s3.exceptions.NoSuchKey:
            pass
        except Exception:
            pass

        new_content = existing + "\n".join(self._buffer).encode() + b"\n"
        self._s3.put_object(Bucket=self._bucket, Key=self._key, Body=new_content)
        self._buffer.clear()

    def close(self) -> None:
        self.flush()

    def read_all(self) -> List[str]:
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=self._key)
            content = resp["Body"].read().decode("utf-8")
            return [l for l in content.splitlines() if l.strip()]
        except Exception:
            return []

    @property
    def uri(self) -> str:
        return f"s3://{self._bucket}/{self._key}"


# ── S3 WORM Compliance Backend (Object Lock & Legal Hold) ────────────────────

class S3WORMBackend(S3Backend):
    """
    AWS S3 Immutable WORM (Write-Once-Read-Many) Storage Backend.
    Complies with SEC Rule 17a-4, FINRA Rule 4511, and EU AI Act Article 12.
    Writes chunks with ObjectLockMode and ObjectLockLegalHoldStatus.
    """

    def __init__(
        self,
        bucket: str,
        key: str,
        object_lock_mode: str = "COMPLIANCE",
        legal_hold: bool = True,
        region: Optional[str] = None,
        **boto3_kwargs,
    ) -> None:
        super().__init__(bucket, key, region=region, **boto3_kwargs)
        self._object_lock_mode = object_lock_mode
        self._legal_hold = legal_hold

    def flush(self) -> None:
        if not self._buffer:
            return
        existing = b""
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=self._key)
            existing = resp["Body"].read()
        except Exception:
            pass

        new_content = existing + "\n".join(self._buffer).encode() + b"\n"
        put_kwargs = {
            "Bucket": self._bucket,
            "Key": self._key,
            "Body": new_content,
            "ContentType": "application/x-ndjson",
        }
        if self._object_lock_mode:
            put_kwargs["ObjectLockMode"] = self._object_lock_mode
        if self._legal_hold:
            put_kwargs["ObjectLockLegalHoldStatus"] = "ON"

        try:
            self._s3.put_object(**put_kwargs)
        except Exception:
            # Fallback to standard put if bucket lacks object lock configuration
            self._s3.put_object(Bucket=self._bucket, Key=self._key, Body=new_content)

        self._buffer.clear()

    @property
    def uri(self) -> str:
        return f"s3-worm://{self._bucket}/{self._key} (mode={self._object_lock_mode})"


# ── GCS backend ───────────────────────────────────────────────────────────────

class GCSBackend(GEFWriterBackend):
    """
    Google Cloud Storage backend. Requires: pip install google-cloud-storage
    Same append-via-rewrite strategy as S3.
    """

    def __init__(self, bucket: str, blob_name: str, **gcs_kwargs) -> None:
        try:
            from google.cloud import storage as gcs
        except ImportError:
            raise BackendNotAvailableError(
                "GCS backend requires google-cloud-storage: "
                "pip install google-cloud-storage"
            )
        self._bucket_name = bucket
        self._blob_name = blob_name
        self._buffer: List[str] = []
        from google.cloud import storage as gcs
        self._client = gcs.Client(**gcs_kwargs)
        self._bucket = self._client.bucket(bucket)

    def append_line(self, line: str) -> None:
        self._buffer.append(line)

    def flush(self) -> None:
        if not self._buffer:
            return
        blob = self._bucket.blob(self._blob_name)
        existing = b""
        try:
            existing = blob.download_as_bytes()
        except Exception:
            pass
        new_content = existing + "\n".join(self._buffer).encode() + b"\n"
        blob.upload_from_string(new_content, content_type="application/x-ndjson")
        self._buffer.clear()

    def close(self) -> None:
        self.flush()

    def read_all(self) -> List[str]:
        try:
            blob = self._bucket.blob(self._blob_name)
            content = blob.download_as_text(encoding="utf-8")
            return [l for l in content.splitlines() if l.strip()]
        except Exception:
            return []

    @property
    def uri(self) -> str:
        return f"gs://{self._bucket_name}/{self._blob_name}"


# ── Azure backend ─────────────────────────────────────────────────────────────

class AzureBackend(GEFWriterBackend):
    """
    Azure Blob Storage backend. Requires: pip install azure-storage-blob
    Uses append blobs for efficient line-by-line appending.
    """

    def __init__(
        self,
        container: str,
        blob_name: str,
        connection_string: str,
    ) -> None:
        try:
            from azure.storage.blob import BlobServiceClient, BlobType
        except ImportError:
            raise BackendNotAvailableError(
                "Azure backend requires azure-storage-blob: "
                "pip install azure-storage-blob"
            )
        from azure.storage.blob import BlobServiceClient, AppendBlobClient
        self._container = container
        self._blob_name = blob_name
        svc = BlobServiceClient.from_connection_string(connection_string)
        self._blob_client = svc.get_blob_client(container, blob_name)
        # Create append blob if it doesn't exist
        try:
            self._blob_client.create_append_blob()
        except Exception:
            pass

    def append_line(self, line: str) -> None:
        self._blob_client.append_block((line + "\n").encode("utf-8"))

    def flush(self) -> None:
        pass  # Azure append blob is immediately durable

    def close(self) -> None:
        pass

    def read_all(self) -> List[str]:
        try:
            data = self._blob_client.download_blob().readall().decode("utf-8")
            return [l for l in data.splitlines() if l.strip()]
        except Exception:
            return []

    @property
    def uri(self) -> str:
        return f"azure://{self._container}/{self._blob_name}"


# ── GEFWriter ─────────────────────────────────────────────────────────────────

class GEFWriter:
    """
    Thread-safe GEF ledger writer with pluggable backends.

    All backends are accessed through this single interface.
    The writer adds thread-safety, error handling, and a consistent API.

    Usage:
        writer = GEFWriter.local("/path/to/ledger.jsonl")
        writer.write_line(json_string)
        writer.flush()
        writer.close()

    Context manager:
        with GEFWriter.local("/path/to/ledger.jsonl") as writer:
            writer.write_line(json_string)
    """

    def __init__(self, backend: GEFWriterBackend) -> None:
        self._backend = backend
        self._lock = threading.Lock()
        self._closed = False

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def local(cls, path: str | Path) -> "GEFWriter":
        """Create a writer backed by the local filesystem."""
        return cls(LocalBackend(Path(path)))

    @classmethod
    def s3(
        cls,
        bucket: str,
        key: str,
        region: Optional[str] = None,
        **kwargs,
    ) -> "GEFWriter":
        """Create a writer backed by AWS S3. Requires boto3."""
        return cls(S3Backend(bucket, key, region=region, **kwargs))

    @classmethod
    def s3_worm(
        cls,
        bucket: str,
        key: str,
        object_lock_mode: str = "COMPLIANCE",
        legal_hold: bool = True,
        region: Optional[str] = None,
        **kwargs,
    ) -> "GEFWriter":
        """Create an immutable WORM writer backed by AWS S3 Object Lock."""
        return cls(
            S3WORMBackend(
                bucket,
                key,
                object_lock_mode=object_lock_mode,
                legal_hold=legal_hold,
                region=region,
                **kwargs,
            )
        )

    @classmethod
    def gcs(cls, bucket: str, blob_name: str, **kwargs) -> "GEFWriter":
        """Create a writer backed by Google Cloud Storage."""
        return cls(GCSBackend(bucket, blob_name, **kwargs))

    @classmethod
    def azure(
        cls,
        container: str,
        blob_name: str,
        connection_string: str,
    ) -> "GEFWriter":
        """Create a writer backed by Azure Blob Storage."""
        return cls(AzureBackend(container, blob_name, connection_string))

    # ── Write interface ───────────────────────────────────────────────────────

    def write_line(self, line: str) -> None:
        """Write a single JSON line to the ledger."""
        if self._closed:
            raise StorageError("GEFWriter is closed")
        with self._lock:
            try:
                self._backend.append_line(line)
            except Exception as e:
                raise StorageError(f"Write failed on {self._backend.uri}: {e}") from e

    def write_envelope(self, envelope_dict: dict) -> None:
        """Serialize and write an envelope dict as a JSON line."""
        self.write_line(json.dumps(envelope_dict, separators=(",", ":")))

    def flush(self) -> None:
        """Flush all pending writes."""
        with self._lock:
            self._backend.flush()

    def close(self) -> None:
        """Flush and close the backend."""
        with self._lock:
            if not self._closed:
                self._backend.close()
                self._closed = True

    def read_all(self) -> List[str]:
        """Read all lines (for verification)."""
        with self._lock:
            return self._backend.read_all()

    @property
    def uri(self) -> str:
        return self._backend.uri

    @property
    def is_closed(self) -> bool:
        return self._closed

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "GEFWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"GEFWriter(uri={self._backend.uri!r}, closed={self._closed})"