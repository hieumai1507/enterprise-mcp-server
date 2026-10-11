"""
FastAPI Server-Sent Events (SSE) and JSON-RPC Transport Endpoints for MCP.
Handles standard MCP SSE sessions, JSON-RPC 2.0 messages, and direct REST invocation.
"""

import asyncio
import json
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from src.core.security import (
    SecurityContext,
    get_current_security_context,
    oauth2_manager,
)
from src.mcp.server import mcp_server

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["MCP Transport"])

# In-memory registry of active SSE client channels: session_id -> asyncio.Queue
active_sessions: dict[str, asyncio.Queue] = {}


class JSONRPCRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: Any | None = Field(default=None)
    method: str = Field(description="MCP Method name (e.g., 'tools/list', 'tools/call', 'initialize')")
    params: dict[str, Any] | None = Field(default_factory=dict)


@router.get("/sse")
async def mcp_sse_endpoint(
    request: Request,
    token: str | None = Query(default=None, description="Bearer token in query param for SSE clients unable to send headers")
):
    """
    MCP Server-Sent Events handshake endpoint.
    Establishes a persistent SSE stream and transmits the session endpoint URL.
    """
    # 1. Authenticate via header or query parameter
    auth_header = request.headers.get("Authorization")
    token_str = None
    if auth_header and auth_header.startswith("Bearer "):
        token_str = auth_header[7:].strip()
    elif token:
        token_str = token

    if not token_str:
        raise HTTPException(status_code=401, detail="Authentication token required for SSE stream")

    try:
        context: SecurityContext = await oauth2_manager.verify_token(token_str)
    except Exception as ex:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {ex!s}")

    session_id = str(uuid.uuid4())
    session_queue: asyncio.Queue = asyncio.Queue()
    active_sessions[session_id] = session_queue

    logger.info("New MCP SSE session established", session_id=session_id, actor=context.sub)

    async def event_generator():
        # First event: Send endpoint URI where JSON-RPC POST messages should be sent
        yield {
            "event": "endpoint",
            "data": f"/messages?session_id={session_id}"
        }

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # Wait for outgoing messages to push to client
                    msg = await asyncio.wait_for(session_queue.get(), timeout=15.0)
                    yield {
                        "event": "message",
                        "data": json.dumps(msg)
                    }
                    session_queue.task_done()
                except TimeoutError:
                    # Keep-alive ping comment
                    yield {
                        "event": "ping",
                        "data": "{}"
                    }
        finally:
            active_sessions.pop(session_id, None)
            logger.info("MCP SSE session closed", session_id=session_id)

    return EventSourceResponse(event_generator())


@router.post("/messages")
async def mcp_post_message(
    request: Request,
    body: JSONRPCRequest,
    session_id: str | None = Query(default=None),
    context: SecurityContext = Depends(get_current_security_context)
):
    """
    Handles JSON-RPC 2.0 requests from MCP clients (e.g. tools/list, tools/call).
    """
    method = body.method
    client_ip = request.client.host if request.client else "127.0.0.1"
    response_payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": body.id
    }

    if method == "initialize":
        response_payload["result"] = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False}
            },
            "serverInfo": {
                "name": "enterprise-postgresql-mcp-server",
                "version": "1.0.0"
            }
        }

    elif method == "tools/list":
        tools = mcp_server.list_available_tools(context)
        response_payload["result"] = {"tools": tools}

    elif method == "tools/call":
        tool_name = body.params.get("name")
        arguments = body.params.get("arguments", {})
        execution_res = await mcp_server.execute_tool(
            tool_name=tool_name,
            arguments=arguments,
            context=context,
            session_id=session_id,
            client_ip=client_ip
        )
        if execution_res.get("isError"):
            response_payload["error"] = {
                "code": -32000,
                "message": execution_res["content"][0]["text"],
                "data": execution_res
            }
        else:
            response_payload["result"] = execution_res

    elif method == "ping":
        response_payload["result"] = {}

    else:
        response_payload["error"] = {
            "code": -32601,
            "message": f"Method '{method}' not found"
        }

    # If active SSE session exists, also push into SSE channel
    if session_id and session_id in active_sessions:
        await active_sessions[session_id].put(response_payload)

    return response_payload


@router.get("/tools")
async def list_tools_rest(context: SecurityContext = Depends(get_current_security_context)):
    """Direct REST endpoint returning accessible tools for the authenticated agent."""
    return {"tools": mcp_server.list_available_tools(context)}


@router.post("/tools/{tool_name}")
async def call_tool_rest(
    tool_name: str,
    payload: dict[str, Any],
    request: Request,
    context: SecurityContext = Depends(get_current_security_context)
):
    """Direct REST endpoint to execute a specific MCP tool."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    result = await mcp_server.execute_tool(
        tool_name=tool_name,
        arguments=payload,
        context=context,
        client_ip=client_ip
    )
    if result.get("isError"):
        status_code = 403 if result.get("errorCode") in ("FORBIDDEN", "GUARDRAIL_BLOCKED") else 400
        raise HTTPException(status_code=status_code, detail=result)
    return result
