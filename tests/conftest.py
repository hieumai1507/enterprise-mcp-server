"""
Pytest Global Configuration, Fixtures, and Mock Factories.
Provides RSA keypairs, JWT generators, and simulated security contexts.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.core.config import settings
from src.core.security import SecurityContext, oauth2_manager


@pytest.fixture(scope="session")
def rsa_keypair():
    """Generates an ephemeral RSA 2048-bit keypair for test JWT signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="session")
def public_pem(rsa_keypair):
    _, public_key = rsa_keypair
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


@pytest.fixture(autouse=True)
def setup_test_security(rsa_keypair):
    """Registers test public key with the security manager for all tests."""
    _, public_key = rsa_keypair
    oauth2_manager.register_test_key("test-key-id", public_key)
    yield


@pytest.fixture
def token_factory(rsa_keypair):
    """Factory helper to forge valid or adversarial JWT tokens for testing."""
    private_key, _ = rsa_keypair

    def _create_token(
        sub: str = "agent-claude-3-5-sonnet",
        client_id: str = "ai-orchestrator-gateway",
        scopes: str = "mcp:tools:read mcp:tools:schema mcp:tools:write",
        roles: list[str] | None = None,
        issuer: str = settings.OIDC_ISSUER,
        audience: str = settings.OIDC_AUDIENCE,
        kid: str = "test-key-id",
        expires_in: int = 3600
    ) -> str:
        roles = roles if roles is not None else ["mcp_analyst_readonly", "mcp_viewer", "mcp_operator_write"]
        payload = {
            "sub": sub,
            "client_id": client_id,
            "scope": scopes,
            "realm_access": {"roles": roles},
            "iss": issuer,
            "aud": audience,
            "exp": int(time.time()) + expires_in,
            "iat": int(time.time()),
            "jti": "test-jwt-uuid"
        }
        headers = {"kid": kid, "alg": "RS256"}
        return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

    return _create_token


@pytest.fixture
def analyst_context():
    return SecurityContext(
        sub="agent-analyst-01",
        client_id="orchestrator-app",
        scope="mcp:tools:read",
        scopes=["mcp:tools:read"],
        roles=["mcp_analyst_readonly"],
        jti="jti-analyst-01"
    )


@pytest.fixture
def viewer_context():
    return SecurityContext(
        sub="agent-viewer-01",
        client_id="orchestrator-app",
        scope="mcp:tools:schema",
        scopes=["mcp:tools:schema"],
        roles=["mcp_viewer"],
        jti="jti-viewer-01"
    )


@pytest.fixture
def operator_context():
    return SecurityContext(
        sub="agent-operator-01",
        client_id="orchestrator-app",
        scope="mcp:tools:write",
        scopes=["mcp:tools:write"],
        roles=["mcp_operator_write"],
        jti="jti-operator-01"
    )


@pytest.fixture
def unauthorized_context():
    return SecurityContext(
        sub="unauthorized-agent-99",
        client_id="unknown-client",
        scope="guest",
        scopes=["guest"],
        roles=["guest_role"],
        jti="jti-unauthorized"
    )
