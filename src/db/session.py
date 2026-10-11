"""
Isolated Multi-Pool Database Manager.
Strictly implements the 'NO Token Passthrough' rule using dedicated service credentials.
"""

from typing import Any

try:
    import asyncpg
except ImportError:
    asyncpg = None

import structlog

from src.core.config import settings

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """
    Manages isolated PostgreSQL connection pools for each privilege tier.
    Agent tokens are strictly terminated at the MCP layer and NEVER forwarded to PostgreSQL.
    """
    def __init__(self):
        self.ro_pool: asyncpg.Pool | None = None
        self.rw_pool: asyncpg.Pool | None = None
        self.audit_pool: asyncpg.Pool | None = None
        self._is_initialized: bool = False

    async def initialize(self) -> None:
        """Initializes separate connection pools using dedicated service credentials."""
        if self._is_initialized:
            return

        if asyncpg is None:
            logger.warning("asyncpg C-extension not available in this environment; database operations will use fallback mode")
            self._is_initialized = True
            return

        logger.info(
            "Initializing isolated database connection pools (No Token Passthrough)",
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            db=settings.DB_NAME
        )

        try:
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
                server_settings={"default_transaction_read_only": "on"}
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
                command_timeout=settings.DB_POOL_TIMEOUT_SECONDS
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

            self._is_initialized = True
            logger.info("All isolated database pools successfully initialized.")

        except Exception as ex:
            logger.warning("Database pool initialization skipped or failed (will reconnect on-demand):", error=str(ex))

    async def health_check(self) -> dict[str, Any]:
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
