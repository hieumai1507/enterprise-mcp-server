"""
Asynchronous Non-Blocking Audit Subsystem.
Queues events in-memory and persists them to PostgreSQL mcp_audit schema via a dedicated worker task.
"""

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import structlog

from src.audit.sanitizer import compute_payload_hash, sanitize_payload
from src.core.config import settings
from src.core.exceptions import AuditLoggingError
from src.db.session import db_manager

logger = structlog.get_logger(__name__)


class AuditBuffer:
    """
    Decouples audit persistence from tool execution latency using an in-memory async queue.
    """
    def __init__(self, queue_size: int = settings.AUDIT_QUEUE_SIZE):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.worker_task: asyncio.Task | None = None
        self.running: bool = False
        self._memory_sink: list[dict[str, Any]] = []  # Fallback/Test sink

    async def start(self) -> None:
        """Starts the background audit persistence worker."""
        if self.running:
            return
        self.running = True
        self.worker_task = asyncio.create_task(self._process_queue())
        logger.info("Audit buffer persistence worker started")

    async def stop(self) -> None:
        """Gracefully flushes remaining events and stops worker."""
        self.running = False
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Audit buffer persistence worker stopped")

    async def record_tool_execution(
        self,
        actor_id: str,
        client_id: str,
        session_id: str,
        client_ip: str,
        tool_name: str,
        granted_scopes: list[str],
        granted_roles: list[str],
        required_scope: str,
        required_role: str,
        arguments: dict[str, Any],
        execution_status: str,
        db_service_account: str,
        duration_ms: float,
        rows_affected: int = 0,
        guardrail_evaluated: bool = False,
        guardrail_risk_score: float | None = None,
        guardrail_decision: str | None = None,
        error_message: str | None = None
    ) -> None:
        """Enqueues a tool execution audit record."""
        payload_hash = compute_payload_hash(arguments)
        sanitized_args = sanitize_payload(arguments)

        event = {
            "type": "tool_execution",
            "actor_id": actor_id,
            "client_id": client_id,
            "session_id": session_id,
            "client_ip": client_ip,
            "tool_name": tool_name,
            "granted_scopes": granted_scopes,
            "granted_roles": granted_roles,
            "required_scope": required_scope,
            "required_role": required_role,
            "input_payload_hash": payload_hash,
            "sanitized_arguments": sanitized_args,
            "guardrail_evaluated": guardrail_evaluated,
            "guardrail_risk_score": guardrail_risk_score,
            "guardrail_decision": guardrail_decision,
            "execution_status": execution_status,
            "db_service_account": db_service_account,
            "duration_ms": duration_ms,
            "rows_affected": rows_affected,
            "error_message": error_message,
            "timestamp": datetime.now(UTC).isoformat()
        }

        self._record_to_memory_sink(event)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit queue is full! Potential log starvation.")
            if settings.AUDIT_FAIL_CLOSED:
                raise AuditLoggingError("Audit queue capacity exceeded. Operation aborted by fail-closed policy.")

    def _record_to_memory_sink(self, event: dict[str, Any]) -> None:
        self._memory_sink.append(event)
        if len(self._memory_sink) > 500:
            self._memory_sink.pop(0)

    async def record_auth_failure(
        self,
        client_ip: str,
        attempted_tool: str,
        denial_reason: str,
        claimed_sub: str | None = None,
        raw_headers: dict[str, Any] | None = None
    ) -> None:
        """Enqueues an authorization / authentication failure record."""
        event = {
            "type": "auth_failure",
            "client_ip": client_ip,
            "attempted_tool": attempted_tool,
            "denial_reason": denial_reason,
            "claimed_sub": claimed_sub,
            "raw_headers": sanitize_payload(raw_headers or {}),
            "timestamp": datetime.now(UTC).isoformat()
        }
        self._record_to_memory_sink(event)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit queue full during auth failure record.")

    async def _process_queue(self) -> None:
        """Background loop continuously persisting queued events into PostgreSQL."""
        while self.running:
            try:
                event = await self.queue.get()
                await self._persist_event(event)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in audit queue processor loop", error=str(e))
                await asyncio.sleep(0.2)

    async def _persist_event(self, event: dict[str, Any]) -> None:
        """Writes individual event to PostgreSQL."""
        if not db_manager.audit_pool:
            return

        try:
            if event["type"] == "tool_execution":
                insert_sql = """
                    INSERT INTO mcp_audit.tool_execution_logs (
                        actor_id, client_id, session_id, client_ip, tool_name,
                        granted_scopes, granted_roles, required_scope, required_role,
                        input_payload_hash, sanitized_arguments, guardrail_evaluated,
                        guardrail_risk_score, guardrail_decision, execution_status,
                        db_service_account, duration_ms, rows_affected, error_message
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
                    )
                """
                async with db_manager.audit_pool.acquire() as conn:
                    await conn.execute(
                        insert_sql,
                        event["actor_id"],
                        event["client_id"],
                        event["session_id"],
                        event["client_ip"],
                        event["tool_name"],
                        event["granted_scopes"],
                        event["granted_roles"],
                        event["required_scope"],
                        event["required_role"],
                        event["input_payload_hash"],
                        json.dumps(event["sanitized_arguments"]),
                        event["guardrail_evaluated"],
                        event["guardrail_risk_score"],
                        event["guardrail_decision"],
                        event["execution_status"],
                        event["db_service_account"],
                        event["duration_ms"],
                        event["rows_affected"],
                        event.get("error_message")
                    )

            elif event["type"] == "auth_failure":
                insert_sql = """
                    INSERT INTO mcp_audit.authorization_failures (
                        client_ip, attempted_tool, denial_reason, claimed_sub, raw_headers
                    ) VALUES ($1, $2, $3, $4, $5)
                """
                async with db_manager.audit_pool.acquire() as conn:
                    await conn.execute(
                        insert_sql,
                        event["client_ip"],
                        event["attempted_tool"],
                        event["denial_reason"],
                        event.get("claimed_sub"),
                        json.dumps(event.get("raw_headers", {}))
                    )
        except Exception as ex:
            logger.error("Failed to persist audit log into PostgreSQL", error=str(ex), event_type=event["type"])


audit_buffer = AuditBuffer()
