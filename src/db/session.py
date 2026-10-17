"""
Isolated Multi-Pool Database Manager.
Strictly implements the 'NO Token Passthrough' rule using dedicated service credentials.
Supports native asyncpg pooling or pure-Python pg8000 pooling when C-extensions are restricted.
"""

import asyncio
import re
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

try:
    import asyncpg
except ImportError:
    asyncpg = None

try:
    import pg8000.dbapi
except ImportError:
    pg8000 = None

import structlog
from src.core.config import settings

logger = structlog.get_logger(__name__)


class PG8000Connection:
    """Wrapper around raw pg8000 DBAPI connection matching asyncpg async interface."""
    def __init__(self, raw_conn: Any, is_read_only: bool = False):
        self._raw_conn = raw_conn
        self._is_read_only = is_read_only

    async def fetch(self, query: str, *params: Any) -> List[Dict[str, Any]]:
        def _exec():
            cur = self._raw_conn.cursor()
            formatted_sql = re.sub(r'\$[0-9]+', '%s', query)
            cur.execute(formatted_sql, list(params))
            if cur.description:
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
            return []
        return await asyncio.to_thread(_exec)

    async def fetchval(self, query: str, *params: Any) -> Any:
        rows = await self.fetch(query, *params)
        if rows:
            return next(iter(rows[0].values()))
        return None

    async def execute(self, query: str, *params: Any) -> str:
        def _exec():
            cur = self._raw_conn.cursor()
            formatted_sql = re.sub(r'\$[0-9]+', '%s', query)
            cur.execute(formatted_sql, list(params))
            self._raw_conn.commit()
            return f"EXECUTED {cur.rowcount}"
        return await asyncio.to_thread(_exec)


class PG8000PoolAdapter:
    """Pure-Python connection pool adapter for environments with restricted C-extensions."""
    def __init__(self, user: str, password: str, host: str, port: int, database: str, is_read_only: bool = False):
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.database = database
        self.is_read_only = is_read_only

    @asynccontextmanager
    async def acquire(self):
        def _connect():
            conn = pg8000.dbapi.connect(
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port,
                database=self.database
            )
            if self.is_read_only:
                cur = conn.cursor()
                cur.execute("SET default_transaction_read_only = 'on'")
                cur.execute(f"SET statement_timeout = '{settings.DB_STATEMENT_TIMEOUT_MS}ms'")
                cur.close()
            else:
                cur = conn.cursor()
                cur.execute(f"SET statement_timeout = '{settings.DB_STATEMENT_TIMEOUT_MS}ms'")
                cur.close()
            return conn

        raw_conn = await asyncio.to_thread(_connect)
        try:
            yield PG8000Connection(raw_conn, self.is_read_only)
        finally:
            await asyncio.to_thread(raw_conn.close)

    async def close(self) -> None:
        pass


class DatabaseManager:
    """
    Manages isolated PostgreSQL connection pools for each privilege tier.
    Agent tokens are strictly terminated at the MCP layer and NEVER forwarded to PostgreSQL.
    """
    def __init__(self):
        self.ro_pool: Any = None
        self.rw_pool: Any = None
        self.audit_pool: Any = None
        self._is_initialized: bool = False

    async def initialize(self) -> None:
        """Initializes separate connection pools using dedicated service credentials."""
        if self._is_initialized:
            return

        logger.info(
            "Initializing isolated database connection pools (No Token Passthrough)",
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            db=settings.DB_NAME
        )

        try:
            if asyncpg is not None:
                # 1. Read-Only Pool (SELECT only, read-only transaction mode)
                self.ro_pool = await asyncpg.create_pool(
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    user=settings.DB_USER_RO,
                    password=settings.DB_PASSWORD_RO,
                    min_size=settings.DB_POOL_MIN_SIZE,
                    max_size=settings.DB_POOL_MAX_SIZE,
                    command_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
                    server_settings={
                        "default_transaction_read_only": "on",
                        "statement_timeout": f"{settings.DB_STATEMENT_TIMEOUT_MS}ms"
                    }
                )

                # 2. Read-Write Pool (DML operations)
                self.rw_pool = await asyncpg.create_pool(
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    user=settings.DB_USER_RW,
                    password=settings.DB_PASSWORD_RW,
                    min_size=settings.DB_POOL_MIN_SIZE,
                    max_size=settings.DB_POOL_MAX_SIZE,
                    command_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
                    server_settings={
                        "statement_timeout": f"{settings.DB_STATEMENT_TIMEOUT_MS}ms"
                    }
                )

                # 3. Audit Pool (Append-only audit writer)
                self.audit_pool = await asyncpg.create_pool(
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    user=settings.DB_USER_AUDIT,
                    password=settings.DB_PASSWORD_AUDIT,
                    min_size=settings.DB_POOL_MIN_SIZE,
                    max_size=settings.DB_POOL_MAX_SIZE,
                    command_timeout=settings.DB_POOL_TIMEOUT_SECONDS
                )
            elif pg8000 is not None:
                logger.info("Using pure-Python pg8000 connection pool adapter for live PostgreSQL connectivity")
                self.ro_pool = PG8000PoolAdapter(
                    user=settings.DB_USER_RO,
                    password=settings.DB_PASSWORD_RO,
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    is_read_only=True
                )
                self.rw_pool = PG8000PoolAdapter(
                    user=settings.DB_USER_RW,
                    password=settings.DB_PASSWORD_RW,
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    is_read_only=False
                )
                self.audit_pool = PG8000PoolAdapter(
                    user=settings.DB_USER_AUDIT,
                    password=settings.DB_PASSWORD_AUDIT,
                    host=settings.DB_HOST,
                    port=settings.DB_PORT,
                    database=settings.DB_NAME,
                    is_read_only=False
                )

            self._is_initialized = True
            logger.info("All isolated database pools successfully initialized.")

        except Exception as ex:
            logger.warning("Database pool initialization skipped or failed (will reconnect on-demand):", error=str(ex))

    async def health_check(self) -> Dict[str, Any]:
        """Performs healthchecks on all active connection pools."""
        status = {"ro_pool": "down", "rw_pool": "down", "audit_pool": "down"}

        if self.ro_pool:
            try:
                async with self.ro_pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                status["ro_pool"] = "healthy"
            except Exception:
                pass

        if self.rw_pool:
            try:
                async with self.rw_pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                status["rw_pool"] = "healthy"
            except Exception:
                pass

        if self.audit_pool:
            try:
                async with self.audit_pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                status["audit_pool"] = "healthy"
            except Exception:
                pass

        return status

    async def close(self) -> None:
        """Gracefully terminates all connection pools."""
        logger.info("Terminating database connection pools...")
        if self.ro_pool:
            await self.ro_pool.close()
            self.ro_pool = None
        if self.rw_pool:
            await self.rw_pool.close()
            self.rw_pool = None
        if self.audit_pool:
            await self.audit_pool.close()
            self.audit_pool = None
        self._is_initialized = False
        logger.info("Database connection pools closed.")


db_manager = DatabaseManager()
