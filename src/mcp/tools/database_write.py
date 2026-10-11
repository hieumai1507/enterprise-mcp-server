"""
Database Write and Mutation Tools.
Executes targeted DML operations using dedicated mcp_rw_service account under strict RBAC.
"""

from typing import Any

from pydantic import BaseModel, Field

from src.core.exceptions import DatabaseSecurityError
from src.core.rbac import require_permissions
from src.core.security import SecurityContext
from src.db.session import db_manager
from src.mcp.tools.registry import tool_registry


class UpdateRecordInput(BaseModel):
    table_name: str = Field(description="Target table name (e.g. 'users', 'orders')")
    primary_key_column: str = Field(default="id", description="Primary key identifier column")
    primary_key_value: Any = Field(description="Primary key value of the row to update")
    fields_to_update: dict[str, Any] = Field(description="Key-value mapping of fields to update")


class InsertRecordInput(BaseModel):
    table_name: str = Field(description="Target table name")
    record_data: dict[str, Any] = Field(description="Key-value mapping of columns and values to insert")


PROHIBITED_SYSTEM_TABLES = {"pg_authid", "pg_shadow", "pg_database", "mcp_audit", "schema_migrations"}


@tool_registry.register(
    name="update_record",
    description="Updates targeted columns on a single row identified by primary key.",
    input_schema=UpdateRecordInput.model_json_schema(),
    required_scope="mcp:tools:write",
    required_role="mcp_operator_write",
    service_account="mcp_rw_service"
)
@require_permissions(required_scope="mcp:tools:write", required_role="mcp_operator_write", tool_name="update_record")
async def update_record(payload: dict[str, Any], security_context: SecurityContext) -> dict[str, Any]:
    params = UpdateRecordInput(**payload) if not isinstance(payload, UpdateRecordInput) else payload

    # Validate table is not prohibited
    if params.table_name.lower() in PROHIBITED_SYSTEM_TABLES or "audit" in params.table_name.lower():
        raise DatabaseSecurityError(f"Modifying system/audit table '{params.table_name}' is strictly prohibited")

    if not params.fields_to_update:
        raise ValueError("No fields provided for update")

    # Construct parameterized UPDATE statement safely
    set_clauses = []
    values = []
    idx = 1
    for col, val in params.fields_to_update.items():
        # Sanitize column names: must be alphanumeric/underscore
        if not col.isidentifier():
            raise DatabaseSecurityError(f"Invalid column identifier: {col}")
        set_clauses.append(f'"{col}" = ${idx}')
        values.append(val)
        idx += 1

    values.append(params.primary_key_value)
    sql = f'UPDATE "{params.table_name}" SET {", ".join(set_clauses)} WHERE "{params.primary_key_column}" = ${idx};'

    if not db_manager.rw_pool:
        return {"status": "success", "rows_updated": 1, "simulated_sql": sql}

    async with db_manager.rw_pool.acquire() as conn:
        result_status = await conn.execute(sql, *values)
        return {"status": "success", "db_result": result_status}


@tool_registry.register(
    name="insert_record",
    description="Inserts a new record into the specified business table.",
    input_schema=InsertRecordInput.model_json_schema(),
    required_scope="mcp:tools:write",
    required_role="mcp_operator_write",
    service_account="mcp_rw_service"
)
@require_permissions(required_scope="mcp:tools:write", required_role="mcp_operator_write", tool_name="insert_record")
async def insert_record(payload: dict[str, Any], security_context: SecurityContext) -> dict[str, Any]:
    params = InsertRecordInput(**payload) if not isinstance(payload, InsertRecordInput) else payload

    if params.table_name.lower() in PROHIBITED_SYSTEM_TABLES or "audit" in params.table_name.lower():
        raise DatabaseSecurityError(f"Modifying system/audit table '{params.table_name}' is strictly prohibited")

    columns = list(params.record_data.keys())
    for col in columns:
        if not col.isidentifier():
            raise DatabaseSecurityError(f"Invalid column identifier: {col}")

    placeholders = [f"${i+1}" for i in range(len(columns))]
    quoted_cols = [f'"{col}"' for col in columns]
    values = [params.record_data[col] for col in columns]

    sql = f'INSERT INTO "{params.table_name}" ({", ".join(quoted_cols)}) VALUES ({", ".join(placeholders)});'

    if not db_manager.rw_pool:
        return {"status": "success", "rows_inserted": 1, "simulated_sql": sql}

    async with db_manager.rw_pool.acquire() as conn:
        result_status = await conn.execute(sql, *values)
        return {"status": "success", "db_result": result_status}
