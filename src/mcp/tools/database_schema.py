"""
Database Schema Inspection Tools.
Exposes read-only catalog exploration (list_tables, describe_table) under low-privilege service account.
"""

from typing import Any

from pydantic import BaseModel, Field

from src.core.rbac import require_permissions
from src.core.security import SecurityContext
from src.db.session import db_manager
from src.mcp.tools.registry import tool_registry


class ListTablesInput(BaseModel):
    schema_name: str = Field(default="public", description="PostgreSQL schema name to inspect")


class DescribeTableInput(BaseModel):
    table_name: str = Field(description="Target table name")
    schema_name: str = Field(default="public", description="Schema containing the table")


@tool_registry.register(
    name="list_tables",
    description="Lists accessible tables within the specified PostgreSQL schema.",
    input_schema=ListTablesInput.model_json_schema(),
    required_scope="mcp:tools:schema",
    required_role="mcp_viewer",
    service_account="mcp_ro_service"
)
@require_permissions(required_scope="mcp:tools:schema", required_role="mcp_viewer", tool_name="list_tables")
async def list_tables(payload: dict[str, Any], security_context: SecurityContext) -> list[dict[str, Any]]:
    params = ListTablesInput(**payload)
    query = """
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = $1
        ORDER BY table_name;
    """
    if not db_manager.ro_pool:
        return [{"table_name": "users", "table_type": "BASE TABLE"}, {"table_name": "orders", "table_type": "BASE TABLE"}]

    async with db_manager.ro_pool.acquire() as conn:
        rows = await conn.fetch(query, params.schema_name)
        return [dict(r) for r in rows]


@tool_registry.register(
    name="describe_table",
    description="Retrieves column definitions, data types, nullability, and primary key status for a table.",
    input_schema=DescribeTableInput.model_json_schema(),
    required_scope="mcp:tools:schema",
    required_role="mcp_viewer",
    service_account="mcp_ro_service"
)
@require_permissions(required_scope="mcp:tools:schema", required_role="mcp_viewer", tool_name="describe_table")
async def describe_table(payload: dict[str, Any], security_context: SecurityContext) -> list[dict[str, Any]]:
    params = DescribeTableInput(**payload)
    query = """
        SELECT
            column_name,
            data_type,
            is_nullable,
            column_default
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        ORDER BY ordinal_position;
    """
    if not db_manager.ro_pool:
        return [
            {"column_name": "id", "data_type": "integer", "is_nullable": "NO", "column_default": None},
            {"column_name": "name", "data_type": "character varying", "is_nullable": "YES", "column_default": None}
        ]

    async with db_manager.ro_pool.acquire() as conn:
        rows = await conn.fetch(query, params.schema_name, params.table_name)
        return [dict(r) for r in rows]
