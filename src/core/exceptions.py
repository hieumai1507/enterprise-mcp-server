"""
Enterprise MCP Server Exception Hierarchy.
Structured security, policy, and domain exceptions.
"""

from typing import Any


class EnterpriseMCPException(Exception):
    """Base exception for all Enterprise MCP Server errors."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class SecurityException(EnterpriseMCPException):
    """Base exception for security boundary failures."""


class AuthenticationError(SecurityException):
    """Raised when OAuth 2.1 token is missing, expired, or cryptographically invalid."""


class InsufficientPermissionsError(SecurityException):
    """Raised when token lacks required scope or application role for tool execution."""
    def __init__(self, message: str, required_scope: str | None = None, required_role: str | None = None):
        super().__init__(message, {"required_scope": required_scope, "required_role": required_role})
        self.required_scope = required_scope
        self.required_role = required_role


class GuardrailViolationError(SecurityException):
    """Raised when TypeSafe AI JEV Classifier-as-a-Judge flags payload as malicious."""
    def __init__(self, message: str, risk_score: float, classification: str, reason: str | None = None):
        super().__init__(
            message,
            {
                "risk_score": risk_score,
                "classification": classification,
                "reason": reason
            }
        )
        self.risk_score = risk_score
        self.classification = classification
        self.reason = reason


class DatabaseSecurityError(SecurityException):
    """Raised when SQL AST parsing detects prohibited operations (DDL, statement chaining)."""


class AuditLoggingError(EnterpriseMCPException):
    """Raised when audit log subsystem fails under fail-closed security mode."""


class ResourceNotFoundError(EnterpriseMCPException):
    """Raised when an MCP resource URI does not exist."""

