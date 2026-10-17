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


@pytest.mark.asyncio
async def test_audit_wal_crash_resilience_and_recovery(tmp_path):
    """
    Verifies that audit events written before an ungraceful stop/crash
    are safely persisted to SQLite WAL and automatically recovered on restart.
    """
    wal_file = str(tmp_path / "test_wal.db")

    # Instance 1: write event and crash (simulate crash without stop or DB flush)
    crash_buf = AuditBuffer(queue_size=10, wal_path=wal_file)
    await crash_buf.record_tool_execution(
        actor_id="crash-agent",
        client_id="crash-client",
        session_id="session-crash",
        client_ip="10.0.0.1",
        tool_name="read_query",
        granted_scopes=["mcp:tools:read"],
        granted_roles=["mcp_analyst_readonly"],
        required_scope="mcp:tools:read",
        required_role="mcp_analyst_readonly",
        arguments={"query": "SELECT 42"},
        execution_status="SUCCESS",
        db_service_account="mcp_ro_service",
        duration_ms=5.0
    )

    # WAL must contain 1 unflushed record
    assert crash_buf.wal.unflushed_count() == 1
    unflushed = crash_buf.wal.fetch_unflushed(limit=10)
    assert len(unflushed) == 1
    assert unflushed[0][1] == "tool_execution"
    assert unflushed[0][2]["actor_id"] == "crash-agent"
    crash_buf.wal.close()

    # Instance 2: Start new server instance using the same WAL file
    recovered_buf = AuditBuffer(queue_size=10, wal_path=wal_file)
    await recovered_buf.start()

    # The recovered buffer should have queued the event for background DB persistence
    assert recovered_buf.queue.qsize() == 1
    recovered_event = await recovered_buf.queue.get()
    assert recovered_event["actor_id"] == "crash-agent"
    assert recovered_event["session_id"] == "session-crash"

    await recovered_buf.stop()
    recovered_buf.wal.close()

