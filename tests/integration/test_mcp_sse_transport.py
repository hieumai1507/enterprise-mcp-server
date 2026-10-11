"""
Integration Tests for FastAPI Transport Layer & MCP Endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_health_check_endpoint():
    """Validates public liveness / readiness probe."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "UP"
        assert "database_pools" in data
        assert "audit_queue_size" in data


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(token_factory):
    """Endpoints requiring authorization return 401 when token is missing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/tools")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mcp_jsonrpc_initialize(token_factory):
    """Tests MCP initialize protocol handshake."""
    token = token_factory()
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        resp = await client.post("/messages", json=payload, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert "serverInfo" in data["result"]
        assert data["result"]["serverInfo"]["name"] == "enterprise-postgresql-mcp-server"


@pytest.mark.asyncio
async def test_mcp_jsonrpc_tools_list_and_call(token_factory):
    """Tests JSON-RPC tools/list and tools/call execution."""
    token = token_factory(
        scopes="mcp:tools:read mcp:tools:schema",
        roles=["mcp_analyst_readonly", "mcp_viewer"]
    )
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. tools/list
        list_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        list_resp = await client.post("/messages", json=list_req, headers=headers)
        assert list_resp.status_code == 200
        tools = list_resp.json()["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "read_query" in tool_names
        assert "list_tables" in tool_names

        # 2. tools/call
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_query",
                "arguments": {
                    "query": "SELECT id, full_name FROM users WHERE id = $1",
                    "parameters": [1]
                }
            }
        }
        call_resp = await client.post("/messages", json=call_req, headers=headers)
        assert call_resp.status_code == 200
        call_data = call_resp.json()
        assert call_data["id"] == 3
        assert "result" in call_data
        assert call_data["result"]["isError"] is False
