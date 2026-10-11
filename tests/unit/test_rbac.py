"""
Unit Tests for Tool-Level Role-Based Access Control (RBAC).
Validates Scope enforcement, Realm Role enforcement, and Prohibited Tool barriers.
"""

import pytest

from src.core.exceptions import InsufficientPermissionsError
from src.core.rbac import evaluate_rbac, require_permissions


def test_rbac_grants_access_when_scope_and_role_present(analyst_context):
    """Access must be permitted when both scope and role requirements are met."""
    # Should not raise
    evaluate_rbac(
        context=analyst_context,
        required_scope="mcp:tools:read",
        required_role="mcp_analyst_readonly",
        tool_name="read_query"
    )


def test_rbac_denies_access_when_scope_missing(analyst_context):
    """Access must be denied when the required scope is absent."""
    with pytest.raises(InsufficientPermissionsError) as exc_info:
        evaluate_rbac(
            context=analyst_context,
            required_scope="mcp:tools:write",
            required_role="mcp_analyst_readonly",
            tool_name="update_record"
        )
    assert "Missing required OAuth scope: 'mcp:tools:write'" in str(exc_info.value)


def test_rbac_denies_access_when_role_missing(analyst_context):
    """Access must be denied when the required application role is absent."""
    with pytest.raises(InsufficientPermissionsError) as exc_info:
        evaluate_rbac(
            context=analyst_context,
            required_scope="mcp:tools:read",
            required_role="mcp_dba_admin",
            tool_name="read_query"
        )
    assert "Missing required application role: 'mcp_dba_admin'" in str(exc_info.value)


def test_rbac_strictly_prohibits_dangerous_ddl_tools(analyst_context):
    """Destructive tools (drop_table, truncate_table) are unconditionally prohibited for AI agents."""
    prohibited_tools = ["drop_table", "truncate_table", "alter_table", "grant_privileges"]
    for dangerous_tool in prohibited_tools:
        with pytest.raises(InsufficientPermissionsError) as exc_info:
            evaluate_rbac(
                context=analyst_context,
                required_scope="mcp:tools:read",
                required_role="mcp_analyst_readonly",
                tool_name=dangerous_tool
            )
        assert "permanently prohibited" in str(exc_info.value)


@pytest.mark.asyncio
async def test_require_permissions_decorator_enforcement(analyst_context, viewer_context):
    """Tests the @require_permissions async decorator on a protected function."""

    @require_permissions(required_scope="mcp:tools:read", required_role="mcp_analyst_readonly")
    async def sample_tool(payload: dict, security_context=None):
        return {"status": "ok"}

    # Allowed for analyst
    res = await sample_tool({"param": 1}, security_context=analyst_context)
    assert res == {"status": "ok"}

    # Denied for viewer
    with pytest.raises(InsufficientPermissionsError):
        await sample_tool({"param": 1}, security_context=viewer_context)
