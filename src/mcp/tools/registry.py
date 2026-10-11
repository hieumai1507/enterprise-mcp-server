"""
Tool Registry and Metadata Manifest for Model Context Protocol.
Maintains tool definitions, JSON schemas, and RBAC authorization requirements.
"""

from collections.abc import Callable
from typing import Any

import structlog
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class ToolDefinition(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]
    required_scope: str
    required_role: str
    service_account: str
    handler: Any


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        required_scope: str,
        required_role: str,
        service_account: str
    ):
        """Decorator to register an MCP tool with schema and RBAC metadata."""
        def decorator(func: Callable):
            tool_def = ToolDefinition(
                name=name,
                description=description,
                input_schema=input_schema,
                required_scope=required_scope,
                required_role=required_role,
                service_account=service_account,
                handler=func
            )
            self._tools[name] = tool_def
            logger.info("Registered MCP tool", tool_name=name, scope=required_scope, role=required_role)
            return func
        return decorator

    def get_tool(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """Returns MCP-compliant tools list representation."""
        return [
            {
                "name": t.name,
                "description": f"{t.description} (Requires Scope: '{t.required_scope}', Role: '{t.required_role}')",
                "inputSchema": t.input_schema
            }
            for t in self._tools.values()
        ]


tool_registry = ToolRegistry()
