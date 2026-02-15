"""
GuardClaw Exception Hierarchy

All exceptions inherit from GuardClawError for easy catching.
"""


class GuardClawError(Exception):
    """Base exception for all GuardClaw errors"""
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class ValidationError(GuardClawError):
    """Raised when data validation fails"""
    pass


class IntegrityError(GuardClawError):
    """Raised when cryptographic integrity check fails"""
    pass


class PolicyError(GuardClawError):
    """Raised when policy evaluation fails"""
    pass


class LedgerError(GuardClawError):
    """Raised when ledger operations fail"""
    pass


class AuthorizationError(GuardClawError):
    """Raised when authorization fails"""
    pass


class SettlementError(GuardClawError):
    """Raised when settlement fails"""
    pass


class ProofExpiredError(AuthorizationError):
    """Raised when authorization proof has expired"""
    pass


class ProofReplayError(AuthorizationError):
    """Raised when proof is reused (replay attack)"""
    pass


class MismatchError(SettlementError):
    """Raised when execution receipt doesn't match authorization proof"""
    pass
