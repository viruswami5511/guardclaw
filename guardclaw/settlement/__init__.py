"""
GuardClaw Settlement Engine

The Settlement Engine reconciles:
- AuthorizationProof (what was ALLOWED)
- ExecutionReceipt (what ACTUALLY HAPPENED)

Critical Invariants:
- Settlement does NOT make authorization decisions
- Settlement does NOT infer intent
- Settlement does NOT normalize data
- Settlement only compares authority vs reality

Design Philosophy:
- Dumb comparison (no semantics)
- Full-fidelity state machine (6 states)
- Immutable settlement records
- One-time proof usage enforcement
"""

from guardclaw.settlement.engine import SettlementEngine

__all__ = ["SettlementEngine"]
