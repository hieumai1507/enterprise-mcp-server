"""
Unit Tests for OAuth 2.1 & PKCE Cryptographic Security.
Validates RFC 7636 PKCE code challenge verification and RFC 9068 JWT verification.
"""

import pytest

from src.core.exceptions import AuthenticationError
from src.core.security import (
    SecurityContext,
    generate_pkce_pair,
    oauth2_manager,
    verify_pkce,
)


def test_pkce_generation_and_verification():
    """Validates that RFC 7636 PKCE S256 verifier correctly matches challenge."""
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    assert verify_pkce(verifier, challenge) is True

    # Tampered verifier must fail
    tampered_verifier = verifier[:-1] + ("A" if verifier[-1] != "A" else "B")
    assert verify_pkce(tampered_verifier, challenge) is False


@pytest.mark.asyncio
async def test_valid_jwt_verification(token_factory):
    """Verifies that a signed, non-expired JWT returns structured SecurityContext."""
    token = token_factory(
        sub="agent-claude-3-5",
        scopes="mcp:tools:read mcp:tools:schema",
        roles=["mcp_analyst_readonly"]
    )
    context = await oauth2_manager.verify_token(token)
    assert isinstance(context, SecurityContext)
    assert context.sub == "agent-claude-3-5"
    assert "mcp:tools:read" in context.scopes
    assert "mcp:tools:schema" in context.scopes
    assert "mcp_analyst_readonly" in context.roles


@pytest.mark.asyncio
async def test_expired_jwt_rejection(token_factory):
    """Verifies that an expired JWT is rejected with AuthenticationError."""
    expired_token = token_factory(expires_in=-300)
    with pytest.raises(AuthenticationError) as exc_info:
        await oauth2_manager.verify_token(expired_token)
    assert "expired" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_invalid_audience_rejection(token_factory):
    """Verifies that a token forged for another audience is rejected."""
    wrong_aud_token = token_factory(audience="unauthorized-target-api")
    with pytest.raises(AuthenticationError) as exc_info:
        await oauth2_manager.verify_token(wrong_aud_token)
    assert "audience" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_invalid_issuer_rejection(token_factory):
    """Verifies that a token from an untrusted issuer is rejected."""
    wrong_iss_token = token_factory(issuer="https://rogue-idp.attacker.com")
    with pytest.raises(AuthenticationError) as exc_info:
        await oauth2_manager.verify_token(wrong_iss_token)
    assert "issuer" in str(exc_info.value).lower()
