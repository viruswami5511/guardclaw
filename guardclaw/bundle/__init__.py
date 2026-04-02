"""
guardclaw/bundle

GEF Evidence Bundle — portable, auditor-ready artifact packaging.

Primary exports:
    GEFBundleExporter   Create .gcbundle folders from .gef ledgers
    BundleExportError   Raised when export preconditions fail
"""

from guardclaw.bundle.exporter import GEFBundleExporter, BundleExportError
from guardclaw.bundle.models import (
    BundleManifest,
    BundleVerification,
    BundlePublicKey,
    GEF_BUNDLE_VERSION,
)

__all__ = [
    "GEFBundleExporter",
    "BundleExportError",
    "BundleManifest",
    "BundleVerification",
    "BundlePublicKey",
    "GEF_BUNDLE_VERSION",
]