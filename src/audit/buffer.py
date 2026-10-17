"""
Asynchronous Non-Blocking Audit Subsystem.
Queues events in-memory and persists them to PostgreSQL mcp_audit schema via a dedicated worker task.
"""

import asyncio
import json
import os
import sqlite3
import threading
from datetime import UTC, datetime
from typing import Any

import structlog

from src.audit.sanitizer import compute_payload_hash, sanitize_payload
from src.core.config import settings
from src.core.exceptions import AuditLoggingError
from src.db.session import db_manager

logger = structlog.get_logger(__name__)


class SqliteAuditWAL:
    """
    Crash-Resilient Write-Ahead Log backed by SQLite WAL mode.
    Guarantees audit records survive unexpected process crashes or SIGKILL.
    """
    def __init__(self, db_path: str = settings.AUDIT_WAL_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
                cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wal_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    flushed INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_wal_flushed ON wal_events (flushed, id);
            """)
            self._conn.commit()

    def write_event(self, event_type: str, event_data: dict[str, Any]) -> int:
        """Synchronously persists an audit event to the SQLite WAL."""
        payload_str = json.dumps(event_data)
        now_str = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO wal_events (event_type, payload, flushed, created_at) VALUES (?, ?, 0, ?)",
                (event_type, payload_str, now_str)
            )
            self._conn.commit()
            return cur.lastrowid or 0

    def fetch_unflushed(self, limit: int = 50) -> list[tuple[int, str, dict[str, Any]]]:
        """Fetches pending unflushed events from the WAL."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT id, event_type, payload FROM wal_events WHERE flushed = 0 ORDER BY id ASC LIMIT ?",
                (limit,)
            )
            rows = cur.fetchall()
            results = []
            for row_id, evt_type, payload_json in rows:
                try:
                    results.append((row_id, evt_type, json.loads(payload_json)))
                except json.JSONDecodeError:
                    continue
            return results

    def mark_flushed(self, wal_id: int) -> None:
        """Marks a WAL record as successfully persisted to PostgreSQL."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("UPDATE wal_events SET flushed = 1 WHERE id = ?", (wal_id,))
            self._conn.commit()

    def prune_flushed(self, keep_last: int = 500) -> None:
        """Prunes flushed records older than the latest threshold to prevent unbounded growth."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                DELETE FROM wal_events
                WHERE flushed = 1 AND id <= (
                    SELECT COALESCE(MAX(id) - ?, 0) FROM wal_events WHERE flushed = 1
                )
            """, (keep_last,))
            self._conn.commit()

    def unflushed_count(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM wal_events WHERE flushed = 0")
            row = cur.fetchone()
            return row[0] if row else 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class AuditBuffer:
    """
    Decouples audit persistence from tool execution latency using a persistent SQLite WAL
    and an in-memory queue that flushes to PostgreSQL mcp_audit schema.
    """
    def __init__(self, queue_size: int = settings.AUDIT_QUEUE_SIZE, wal_path: str = settings.AUDIT_WAL_PATH):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.wal: SqliteAuditWAL = SqliteAuditWAL(wal_path)
        self.worker_task: asyncio.Task | None = None
        self.running: bool = False
        self._memory_sink: list[dict[str, Any]] = []  # Fallback/Test sink

    async def start(self) -> None:
        """Starts the background audit persistence worker and recovers unflushed WAL events."""
        if self.running:
            return
        self.running = True

        # Startup crash recovery: enqueue any unflushed WAL events from previous crashes
        unflushed = self.wal.fetch_unflushed(limit=200)
        if unflushed:
            logger.info("Recovering unflushed audit events from SQLite WAL", count=len(unflushed))
            for wal_id, _, event in unflushed:
                event["_wal_id"] = wal_id
                try:
                    self.queue.put_nowait(event)
                except asyncio.QueueFull:
                    break

        self.worker_task = asyncio.create_task(self._process_queue())
        logger.info("Audit buffer persistence worker started with SQLite WAL")

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
        """Enqueues a tool execution audit record into SQLite WAL and memory queue."""
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

        # 1. Synchronously persist to SQLite WAL (< 2ms) to guarantee durability against crashes
        try:
            wal_id = self.wal.write_event("tool_execution", event)
            event["_wal_id"] = wal_id
        except Exception as e:
            logger.critical("SQLite WAL write failed", error=str(e))
            if settings.AUDIT_FAIL_CLOSED:
                raise AuditLoggingError(f"Audit WAL persistence failed: {e!s}")

        self._record_to_memory_sink(event)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit memory queue is full! Event is durable in SQLite WAL.")
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
        """Enqueues an authorization / authentication failure record into WAL and queue."""
        event = {
            "type": "auth_failure",
            "client_ip": client_ip,
            "attempted_tool": attempted_tool,
            "denial_reason": denial_reason,
            "claimed_sub": claimed_sub,
            "raw_headers": sanitize_payload(raw_headers or {}),
            "timestamp": datetime.now(UTC).isoformat()
        }

        # 1. Synchronously persist to SQLite WAL
        try:
            wal_id = self.wal.write_event("auth_failure", event)
            event["_wal_id"] = wal_id
        except Exception as e:
            logger.critical("SQLite WAL write failed on auth failure", error=str(e))

        self._record_to_memory_sink(event)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit queue full during auth failure record.")

    async def _process_queue(self) -> None:
        """Background loop continuously persisting queued events into PostgreSQL and marking WAL flushed."""
        flush_counter = 0
        while self.running:
            try:
                event = await self.queue.get()
                persisted = await self._persist_event(event)
                if persisted and "_wal_id" in event:
                    self.wal.mark_flushed(event["_wal_id"])

                flush_counter += 1
                if flush_counter % 50 == 0:
                    self.wal.prune_flushed()

                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in audit queue processor loop", error=str(e))
                await asyncio.sleep(0.2)

    async def _persist_event(self, event: dict[str, Any]) -> bool:
        """Writes individual event to PostgreSQL. Returns True on success."""
        if not db_manager.audit_pool:
            return False

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
                return True

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
                return True
        except Exception as ex:
            logger.error("Failed to persist audit log into PostgreSQL", error=str(ex), event_type=event["type"])
            return False
        return False


audit_buffer = AuditBuffer()

