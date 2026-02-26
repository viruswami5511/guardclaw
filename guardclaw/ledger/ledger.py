"""
GuardClaw GEF: Ledger module.

LedgerEntry and the old Ledger class are removed.
GEFLedger (in guardclaw.core.emitter) is the single ledger implementation.

This module re-exports GEFLedger for import compatibility.
"""

from guardclaw.core.emitter import GEFLedger

__all__ = ["GEFLedger"]
