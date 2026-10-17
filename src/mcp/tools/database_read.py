"""
Database Read Query Tools.
Executes parameterized SELECT queries using dedicated mcp_ro_service account with AST validation.
"""

from typing import Any

from pydantic import BaseModel, Field

from src.core.rbac import require_permissions
from src.core.security import SecurityContext
from src.db.query_builder import enforce_query_governor, validate_read_only_sql
from src.db.session import db_manager
from src.mcp.tools.registry import tool_registry


class ReadQueryInput(BaseModel):
    query: str = Field(description="Parameterized SELECT query using positional parameters ($1, $2, ...)")
    parameters: list[Any] = Field(default_factory=list, description="Positional query parameters matching query placeholders")


class ExecuteReportInput(BaseModel):
    report_name: str = Field(description="Name of the pre-approved analytical view or report")
    filters: dict[str, Any] = Field(default_factory=dict, description="Filter criteria")


PREDEFINED_REPORTS = {
    "active_user_summary": "SELECT department, count(*) as user_count FROM users GROUP BY department;",
    "daily_order_volume": "SELECT status, count(*) as count, sum(total_amount) as revenue FROM orders GROUP BY status;"
}


@tool_registry.register(
    name="read_query",
    description="Executes a safe, parameterized read-only SELECT query against PostgreSQL.",
    input_schema=ReadQueryInput.model_json_schema(),
    required_scope="mcp:tools:read",
    required_role="mcp_analyst_readonly",
    service_account="mcp_ro_service"
)
@require_permissions(required_scope="mcp:tools:read", required_role="mcp_analyst_readonly", tool_name="read_query")
async def execute_read_query(payload: dict[str, Any], security_context: SecurityContext) -> list[dict[str, Any]]:
    # 1. Pydantic parameter validation
    params = ReadQueryInput(**payload) if not isinstance(payload, ReadQueryInput) else payload

    # 2. SQL AST Sanity Check & Table Access Control
    validate_read_only_sql(params.query)

    # 3. Apply Query Governor (enforce LIMIT 100 to prevent unbounded memory consumption)
    governed_query = enforce_query_governor(params.query)

    # 4. Execution against read-only pool (with transaction read only enabled)
    if not db_manager.ro_pool:
        # Development / Unit Test simulated response
        return [{"status": "success", "rows_mocked": 1, "query_echo": governed_query}]

    async with db_manager.ro_pool.acquire() as conn:
        records = await conn.fetch(governed_query, *params.parameters)
        return [dict(rec) for rec in records]


@tool_registry.register(
    name="execute_report",
    description="Executes a pre-approved, audited analytical report view.",
    input_schema=ExecuteReportInput.model_json_schema(),
    required_scope="mcp:tools:read",
    required_role="mcp_analyst_readonly",
    service_account="mcp_ro_service"
)
@require_permissions(required_scope="mcp:tools:read", required_role="mcp_analyst_readonly", tool_name="execute_report")
async def execute_report(payload: dict[str, Any], security_context: SecurityContext) -> list[dict[str, Any]]:
    params = ExecuteReportInput(**payload)
    if params.report_name not in PREDEFINED_REPORTS:
        raise ValueError(
            f"Unknown report '{params.report_name}'. Approved reports: {list(PREDEFINED_REPORTS.keys())}"
        )

    sql = PREDEFINED_REPORTS[params.report_name]
    validate_read_only_sql(sql)

    if not db_manager.ro_pool:
        return [{"report": params.report_name, "status": "executed"}]

    async with db_manager.ro_pool.acquire() as conn:
        records = await conn.fetch(sql)
        return [dict(rec) for rec in records]
