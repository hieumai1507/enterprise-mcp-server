"""
Tool-Level Role-Based Access Control (RBAC) Engine.
Enforces OAuth 2.1 Scope and Application Role policy decisions.
"""

from collections.abc import Callable
from functools import wraps

import structlog

from src.core.exceptions import InsufficientPermissionsError
from src.core.security import SecurityContext

logger = structlog.get_logger(__name__)

# List of operations strictly prohibited for automated AI agent execution
PROHIBITED_AI_TOOLS = {
    "drop_table",
    "drop_database",
    "truncate_table",
    "alter_table",
    "grant_privileges",
    "revoke_privileges",
    "execute_arbitrary_ddl"
}


def evaluate_rbac(
    context: SecurityContext,
    required_scope: str,
    required_role: str,
    tool_name: str | None = None
) -> None:
    """
    Evaluates whether the provided SecurityContext possesses the required scope and role.
    Raises InsufficientPermissionsError if access is denied.
    """
    # 1. Hardcoded DDL / Destructive Operation Block
    if tool_name and tool_name.lower() in PROHIBITED_AI_TOOLS:
        logger.critical(
            "RBAC Denied: Prohibited Tool Invocated by Agent",
            actor=context.sub,
            client_id=context.client_id,
            tool=tool_name
        )
        raise InsufficientPermissionsError(
            f"Tool '{tool_name}' is permanently prohibited for AI agent execution by policy",
            required_scope="PROHIBITED",
            required_role="PROHIBITED"
        )

    # 2. OAuth Scope Validation
    if required_scope not in context.scopes:
        logger.warning(
            "RBAC Denied: Insufficient OAuth Scope",
            actor=context.sub,
            client_id=context.client_id,
            tool=tool_name,
            required_scope=required_scope,
            granted_scopes=context.scopes
        )
        raise InsufficientPermissionsError(
            f"Missing required OAuth scope: '{required_scope}'",
            required_scope=required_scope,
            required_role=required_role
        )

    # 3. Application Realm Role Validation
    if required_role not in context.roles:
        logger.warning(
            "RBAC Denied: Insufficient Application Role",
            actor=context.sub,
            client_id=context.client_id,
            tool=tool_name,
            required_role=required_role,
            granted_roles=context.roles
        )
        raise InsufficientPermissionsError(
            f"Missing required application role: '{required_role}'",
            required_scope=required_scope,
            required_role=required_role
        )

    logger.debug(
        "RBAC Access Granted",
        actor=context.sub,
        client_id=context.client_id,
        tool=tool_name,
        role=required_role
    )


def require_permissions(required_scope: str, required_role: str, tool_name: str | None = None):
    """
    Declarative decorator for tool handlers enforcing OAuth scope and role verification.
    """
    def decorator(func: Callable):
        inferred_tool_name = tool_name or func.__name__

        @wraps(func)
        async def wrapper(*args, **kwargs):
            security_context = kwargs.get("security_context")
            if not security_context:
                # Check args if passed positionally
                for arg in args:
                    if isinstance(arg, SecurityContext):
                        security_context = arg
                        break

            if not security_context or not isinstance(security_context, SecurityContext):
                raise InsufficientPermissionsError("Unauthenticated or invalid security context supplied to tool")

            evaluate_rbac(
                context=security_context,
                required_scope=required_scope,
                required_role=required_role,
                tool_name=inferred_tool_name
            )

            return await func(*args, **kwargs)

        wrapper._required_scope = required_scope
        wrapper._required_role = required_role
        wrapper._tool_name = inferred_tool_name
        return wrapper

    return decorator
