"""
Model Context Protocol (MCP) Server Core Engine.
Coordinates Authentication, Tool-Level RBAC, JEV AI Guardrail, and Audit Logging.
"""

import time
import uuid
from typing import Any

import structlog

import src.mcp.tools.database_read

# Ensure tools are imported and registered
import src.mcp.tools.database_schema
import src.mcp.tools.database_write  # noqa: F401
from src.audit.buffer import audit_buffer
from src.core.exceptions import (
    DatabaseSecurityError,
    GuardrailViolationError,
    InsufficientPermissionsError,
)
from src.core.rbac import evaluate_rbac
from src.core.security import SecurityContext
from src.mcp.middleware.guardrail_middleware import jev_guardrail
from src.mcp.tools.registry import tool_registry

logger = structlog.get_logger(__name__)


class MCPServerEngine:
    """Core Policy Decision Point and Dispatcher for Enterprise Model Context Protocol."""

    def list_available_tools(self, context: SecurityContext) -> list[dict[str, Any]]:
        """
        Returns tools list filtered by the caller's granted scopes and roles,
        or full list with embedded RBAC requirements.
        """
        all_tools = tool_registry.list_tools()
        accessible_tools = []
        for t_dict in all_tools:
            tool_name = t_dict["name"]
            tool_def = tool_registry.get_tool(tool_name)
            if tool_def:
                # Include tools where scope and role match
                has_scope = tool_def.required_scope in context.scopes
                has_role = tool_def.required_role in context.roles
                t_dict["is_authorized"] = has_scope and has_role
                accessible_tools.append(t_dict)
        return accessible_tools

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: SecurityContext,
        session_id: str | None = None,
        client_ip: str = "127.0.0.1"
    ) -> dict[str, Any]:
        """
        Full 5-phase execution pipeline:
        1. Tool Lookup
        2. Tool-Level RBAC Evaluation (Scope + Role)
        3. Real-Time AI Intent Guardrail (TypeSafe AI JEV Classifier)
        4. Safe Database Execution (Isolated Service Account)
        5. Asynchronous Audit Log Persistence
        """
        session = session_id or str(uuid.uuid4())
        start_time = time.perf_counter()

        tool_def = tool_registry.get_tool(tool_name)
        if not tool_def:
            await audit_buffer.record_auth_failure(
                client_ip=client_ip,
                attempted_tool=tool_name,
                denial_reason=f"Tool '{tool_name}' not found",
                claimed_sub=context.sub
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Tool '{tool_name}' does not exist"}]
            }

        guardrail_result = {"risk_score": 0.0, "classification": "SKIPPED", "reason": ""}
        error_msg = None
        result_payload = None
        rows_count = 0

        try:
            # Phase 1: Tool-Level RBAC Enforcement
            evaluate_rbac(
                context=context,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                tool_name=tool_name
            )

            # Phase 2: AI Guardrail Intent Evaluation (JEV Model)
            guardrail_result = await jev_guardrail.verify_and_gate(
                tool_name=tool_name,
                arguments=arguments,
                agent_context={"sub": context.sub, "client_id": context.client_id, "roles": context.roles}
            )

            # Phase 3: Isolated Service Account Execution (NO Token Passthrough)
            result_payload = await tool_def.handler(arguments, security_context=context)

            if isinstance(result_payload, list):
                rows_count = len(result_payload)
            elif isinstance(result_payload, dict):
                rows_count = result_payload.get("rows_updated", result_payload.get("rows_inserted", 1))

            duration_ms = (time.perf_counter() - start_time) * 1000

            # Phase 4: Async Audit Recording (Success)
            await audit_buffer.record_tool_execution(
                actor_id=context.sub,
                client_id=context.client_id,
                session_id=session,
                client_ip=client_ip,
                tool_name=tool_name,
                granted_scopes=context.scopes,
                granted_roles=context.roles,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                arguments=arguments,
                execution_status="SUCCESS",
                db_service_account=tool_def.service_account,
                duration_ms=duration_ms,
                rows_affected=rows_count,
                guardrail_evaluated=True,
                guardrail_risk_score=guardrail_result.get("risk_score"),
                guardrail_decision=guardrail_result.get("classification")
            )

            return {
                "isError": False,
                "content": [{"type": "text", "text": str(result_payload)}],
                "data": result_payload
            }

        except InsufficientPermissionsError as rbac_err:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = str(rbac_err)
            await audit_buffer.record_tool_execution(
                actor_id=context.sub,
                client_id=context.client_id,
                session_id=session,
                client_ip=client_ip,
                tool_name=tool_name,
                granted_scopes=context.scopes,
                granted_roles=context.roles,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                arguments=arguments,
                execution_status="AUTHORIZATION_DENIED",
                db_service_account=tool_def.service_account,
                duration_ms=duration_ms,
                error_message=error_msg
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Permission Denied: {error_msg}"}],
                "errorCode": "FORBIDDEN"
            }

        except GuardrailViolationError as guard_err:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = str(guard_err)
            await audit_buffer.record_tool_execution(
                actor_id=context.sub,
                client_id=context.client_id,
                session_id=session,
                client_ip=client_ip,
                tool_name=tool_name,
                granted_scopes=context.scopes,
                granted_roles=context.roles,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                arguments=arguments,
                execution_status="GUARDRAIL_BLOCKED",
                db_service_account=tool_def.service_account,
                duration_ms=duration_ms,
                guardrail_evaluated=True,
                guardrail_risk_score=guard_err.risk_score,
                guardrail_decision=guard_err.classification,
                error_message=error_msg
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Security Guardrail Violation: {error_msg}"}],
                "errorCode": "GUARDRAIL_BLOCKED"
            }

        except DatabaseSecurityError as sec_err:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = str(sec_err)
            await audit_buffer.record_tool_execution(
                actor_id=context.sub,
                client_id=context.client_id,
                session_id=session,
                client_ip=client_ip,
                tool_name=tool_name,
                granted_scopes=context.scopes,
                granted_roles=context.roles,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                arguments=arguments,
                execution_status="VALIDATION_ERROR",
                db_service_account=tool_def.service_account,
                duration_ms=duration_ms,
                error_message=error_msg
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Database Security Violation: {error_msg}"}],
                "errorCode": "DATABASE_SECURITY_ERROR"
            }

        except Exception as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = str(ex)
            await audit_buffer.record_tool_execution(
                actor_id=context.sub,
                client_id=context.client_id,
                session_id=session,
                client_ip=client_ip,
                tool_name=tool_name,
                granted_scopes=context.scopes,
                granted_roles=context.roles,
                required_scope=tool_def.required_scope,
                required_role=tool_def.required_role,
                arguments=arguments,
                execution_status="EXECUTION_ERROR",
                db_service_account=tool_def.service_account,
                duration_ms=duration_ms,
                error_message=error_msg
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Internal Tool Execution Error: {error_msg}"}],
                "errorCode": "INTERNAL_ERROR"
            }


mcp_server = MCPServerEngine()
