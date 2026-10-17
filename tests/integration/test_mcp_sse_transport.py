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


@pytest.mark.asyncio
async def test_mcp_jsonrpc_resources_list_and_read(token_factory):
    """
    Validates MCP Resources specification (2024-11-05):
    - resources/list discovers 'postgres://schema/summary'
    - resources/read returns Markdown database schema
    """
    token = token_factory(
        scopes="mcp:tools:read mcp:tools:schema",
        roles=["mcp_analyst_readonly", "mcp_viewer"]
    )
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test resources/list
        list_req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/list",
            "params": {}
        }
        resp = await client.post("/messages", json=list_req, headers=headers)
        assert resp.status_code == 200
        res_data = resp.json()["result"]["resources"]
        assert len(res_data) >= 1
        assert res_data[0]["uri"] == "postgres://schema/summary"

        # 2. Test resources/read
        read_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": {"uri": "postgres://schema/summary"}
        }
        read_resp = await client.post("/messages", json=read_req, headers=headers)
        assert read_resp.status_code == 200
        contents = read_resp.json()["result"]["contents"]
        assert len(contents) == 1
        assert contents[0]["uri"] == "postgres://schema/summary"
        assert "# PostgreSQL Database Schema Summary" in contents[0]["text"]
        assert "users" in contents[0]["text"]


@pytest.mark.asyncio
async def test_mcp_token_revocation_endpoint_blocks_future_requests(token_factory):
    """
    Validates RFC 7009 / RFC 7662 token revocation:
    Revoking a token JTI immediately rejects subsequent requests with 401 Unauthorized.
    """
    target_jti = "revoked-agent-uuid-999"
    token = token_factory(
        sub="compromised-agent",
        scopes="mcp:tools:read",
        roles=["mcp_analyst_readonly"]
    )
    # Forge token with target_jti
    import time
    import jwt
    from src.core.config import settings
    from tests.conftest import rsa_keypair
    # We can invoke /auth/revoke with explicit jti
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Revoke the token using its raw token string
        revoke_resp = await client.post("/auth/revoke", json={"token": token})
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["status"] == "revoked"

        # Attempt to access protected endpoint with the revoked token
        blocked_resp = await client.get("/tools", headers=headers)
        assert blocked_resp.status_code == 401
        assert "revoked" in blocked_resp.json()["detail"].lower()

