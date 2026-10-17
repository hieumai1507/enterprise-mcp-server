"""
Enterprise MCP Client Integration Example.
Demonstrates how AI Orchestrators (LangGraph, CrewAI, AutoGen, Custom Gateways)
connect to the Enterprise PostgreSQL MCP Server via OAuth 2.1 with PKCE.
"""

import httpx
import json
import base64
import os
import hashlib


class EnterpriseMCPClient:
    def __init__(self, mcp_server_url: str, idp_token_url: str, client_id: str):
        self.mcp_url = mcp_server_url.rstrip("/")
        self.idp_url = idp_token_url
        self.client_id = client_id
        self.access_token = None

    def generate_pkce(self) -> tuple[str, str]:
        """Generates RFC 7636 PKCE code_verifier and code_challenge."""
        verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
        challenge_bytes = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
        return verifier, challenge

    async def authenticate_service_account(self, client_secret: str, scope: str = "mcp:tools:read mcp:tools:schema"):
        """Fetches OAuth 2.1 access token using client credentials or authorization code grant."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.idp_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": client_secret,
                    "scope": scope
                }
            )
            resp.raise_for_status()
            data = resp.json()
            self.access_token = data["access_token"]
            return self.access_token

    def set_bearer_token(self, token: str):
        """Sets an already acquired agent access token."""
        self.access_token = token

    async def list_tools(self) -> list:
        """Retrieves authorized tools available for this agent's identity."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.mcp_url}/tools", headers=headers)
            resp.raise_for_status()
            return resp.json()["tools"]

    async def execute_tool(self, tool_name: str, arguments: dict) -> dict:
        """Executes a tool on the Enterprise MCP Server with intent guardrails & RBAC."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.mcp_url}/tools/{tool_name}",
                headers=headers,
                json=arguments
            )
            return resp.json()


# Usage demonstration
if __name__ == "__main__":
    import asyncio

    async def run_example():
        client = EnterpriseMCPClient(
            mcp_server_url="http://localhost:8000",
            idp_token_url="http://localhost:8080/realms/ai-services/protocol/openid-connect/token",
            client_id="ai-orchestrator-gateway"
        )

        print("[1] Initialized Enterprise MCP Client")
        # In production: authenticate via IdP or inject token
        # client.authenticate_service_account(client_secret="...")

    asyncio.run(run_example())
