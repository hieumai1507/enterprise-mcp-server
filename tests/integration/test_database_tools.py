"""
Integration Tests for Database Tool Handlers & AST Protections.
"""

import pytest

from src.core.exceptions import DatabaseSecurityError
from src.db.query_builder import validate_read_only_sql
from src.mcp.server import mcp_server


def test_sql_ast_rejects_multi_statements():
    multi_sql = "SELECT id FROM users; DROP TABLE users;"
    with pytest.raises(DatabaseSecurityError) as exc:
        validate_read_only_sql(multi_sql)
    assert "Multi-statement" in str(exc.value)


def test_sql_ast_rejects_prohibited_dml_ddl():
    prohibited_queries = [
        "DELETE FROM users WHERE id = 1;",
        "UPDATE users SET email = 'bad';",
        "DROP TABLE users;",
        "TRUNCATE users;",
        "ALTER TABLE users ADD COLUMN h4ck TEXT;"
    ]
    for q in prohibited_queries:
        with pytest.raises(DatabaseSecurityError) as exc:
            validate_read_only_sql(q)
        assert "Only SELECT" in str(exc.value) or "Prohibited" in str(exc.value)


def test_sql_ast_rejects_dangerous_internal_functions():
    with pytest.raises(DatabaseSecurityError) as exc:
        validate_read_only_sql("SELECT pg_sleep(10);")
    assert "pg_sleep" in str(exc.value)


@pytest.mark.asyncio
async def test_read_query_tool_authorized(analyst_context):
    """Analyst context possesses scope 'mcp:tools:read' and role 'mcp_analyst_readonly'."""
    res = await mcp_server.execute_tool(
        tool_name="read_query",
        arguments={"query": "SELECT id, full_name FROM users WHERE id = $1", "parameters": [1]},
        context=analyst_context
    )
    assert res["isError"] is False
    assert "content" in res


@pytest.mark.asyncio
async def test_read_query_tool_denied_for_viewer(viewer_context):
    """Viewer context possesses 'mcp:tools:schema' but lacks 'mcp:tools:read'."""
    res = await mcp_server.execute_tool(
        tool_name="read_query",
        arguments={"query": "SELECT id FROM users", "parameters": []},
        context=viewer_context
    )
    assert res["isError"] is True
    assert res["errorCode"] == "FORBIDDEN"
    assert "Missing required OAuth scope: 'mcp:tools:read'" in res["content"][0]["text"]


@pytest.mark.asyncio
async def test_update_record_denied_for_analyst(analyst_context):
    """Analyst cannot execute write tool 'update_record'."""
    res = await mcp_server.execute_tool(
        tool_name="update_record",
        arguments={
            "table_name": "users",
            "primary_key_column": "id",
            "primary_key_value": 1,
            "fields_to_update": {"full_name": "Updated Name"}
        },
        context=analyst_context
    )
    assert res["isError"] is True
    assert res["errorCode"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_update_record_allowed_for_operator(operator_context):
    """Operator possesses required scope 'mcp:tools:write' and role 'mcp_operator_write'."""
    res = await mcp_server.execute_tool(
        tool_name="update_record",
        arguments={
            "table_name": "users",
            "primary_key_column": "id",
            "primary_key_value": 1,
            "fields_to_update": {"full_name": "Alice Verified"}
        },
        context=operator_context
    )
    assert res["isError"] is False
    assert res["data"]["status"] == "success"


@pytest.mark.asyncio
async def test_update_record_rejects_audit_tampering(operator_context):
    """Targeting audit tables raises DatabaseSecurityError."""
    res = await mcp_server.execute_tool(
        tool_name="update_record",
        arguments={
            "table_name": "mcp_audit.tool_execution_logs",
            "primary_key_column": "event_id",
            "primary_key_value": "some-id",
            "fields_to_update": {"execution_status": "TAMPERED"}
        },
        context=operator_context
    )
    assert res["isError"] is True
    assert res["errorCode"] == "DATABASE_SECURITY_ERROR"
    assert "audit table" in res["content"][0]["text"].lower()
