"""
Unit Tests for Audit Buffer and Event Ingestion.
"""

import asyncio

import pytest

from src.audit.buffer import AuditBuffer


@pytest.mark.asyncio
async def test_audit_buffer_lifecycle_and_record():
    """Validates audit buffer lifecycle, enqueueing, and memory sink capture."""
    buf = AuditBuffer(queue_size=100)
    await buf.start()
    assert buf.running is True

    # Record tool execution
    await buf.record_tool_execution(
        actor_id="test-agent",
        client_id="test-client",
        session_id="session-1",
        client_ip="127.0.0.1",
        tool_name="read_query",
        granted_scopes=["mcp:tools:read"],
        granted_roles=["mcp_analyst_readonly"],
        required_scope="mcp:tools:read",
        required_role="mcp_analyst_readonly",
        arguments={"query": "SELECT 1"},
        execution_status="SUCCESS",
        db_service_account="mcp_ro_service",
        duration_ms=12.5
    )

    # Record auth failure
    await buf.record_auth_failure(
        client_ip="127.0.0.1",
        attempted_tool="drop_table",
        denial_reason="Prohibited tool",
        claimed_sub="malicious-agent"
    )

    # Give worker loop a tick to process
    await asyncio.sleep(0.1)

    assert len(buf._memory_sink) >= 2
    assert buf._memory_sink[0]["type"] == "tool_execution"
    assert buf._memory_sink[0]["actor_id"] == "test-agent"
    assert buf._memory_sink[1]["type"] == "auth_failure"
    assert buf._memory_sink[1]["attempted_tool"] == "drop_table"

    await buf.stop()
    assert buf.running is False
