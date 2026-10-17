"""
OAuth 2.1 & PKCE Authentication and Cryptographic Token Verification.
Enforces RFC 9068 JWT verification, JWKS key rotation, and PKCE S256 verification.
"""

import base64
import hashlib
import os
import secrets
from typing import Any

import httpx
import jwt
import structlog
from cachetools import TTLCache
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from src.core.config import settings
from src.core.exceptions import AuthenticationError

logger = structlog.get_logger(__name__)
security_scheme = HTTPBearer(auto_error=False)


class SecurityContext(BaseModel):
    """Normalized security context extracted from verified OAuth 2.1 token."""
    sub: str = Field(description="Subject identifier (Agent or User ID)")
    client_id: str = Field(description="OAuth 2.1 Client ID")
    scope: str = Field(default="", description="Space-delimited OAuth scopes")
    scopes: list[str] = Field(default_factory=list, description="Parsed scopes")
    roles: list[str] = Field(default_factory=list, description="Application realm roles")
    jti: str | None = Field(default=None, description="JWT ID for replay detection")
    raw_token: str | None = Field(default=None, description="Original token string")
    claims: dict[str, Any] = Field(default_factory=dict, description="Full verified claims payload")

    @classmethod
    def from_claims(cls, claims: dict[str, Any], raw_token: str | None = None) -> "SecurityContext":
        scope_str = claims.get("scope", "")
        parsed_scopes = [s for s in scope_str.split(" ") if s]

        # Support Keycloak realm_access, Auth0 roles, or standard role claims
        roles = []
        if "realm_access" in claims and isinstance(claims["realm_access"], dict):
            roles.extend(claims["realm_access"].get("roles", []))
        if "roles" in claims and isinstance(claims["roles"], list):
            roles.extend(claims["roles"])

        return cls(
            sub=claims.get("sub", "unknown"),
            client_id=claims.get("client_id") or claims.get("azp") or "unknown",
            scope=scope_str,
            scopes=parsed_scopes,
            roles=list(set(roles)),
            jti=claims.get("jti"),
            raw_token=raw_token,
            claims=claims
        )


def generate_pkce_pair() -> tuple[str, str]:
    """Generates an RFC 7636 compliant (code_verifier, code_challenge) pair using S256."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    challenge_bytes = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
    return verifier, challenge


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verifies that SHA256(code_verifier) matches code_challenge (RFC 7636)."""
    expected_bytes = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected_challenge = base64.urlsafe_b64encode(expected_bytes).decode("utf-8").rstrip("=")
    return secrets.compare_digest(expected_challenge, code_challenge)


class OAuth21SecurityManager:
    """Manages JWKS retrieval, caching, and cryptographic verification for OAuth 2.1 tokens."""

    def __init__(self):
        self.jwks_cache = TTLCache(maxsize=16, ttl=settings.OIDC_JWKS_CACHE_TTL_SECONDS)
        self.test_public_keys: dict[str, Any] = {}
        self.revoked_jtis: set[str] = set()

    def register_test_key(self, kid: str, public_key: Any) -> None:
        """Allows registration of mock/test public keys for offline testing."""
        self.test_public_keys[kid] = public_key

    def revoke_token(self, jti: str) -> None:
        """Revokes a token identifier (JTI), immediately blocking subsequent requests (RFC 7662)."""
        if jti:
            self.revoked_jtis.add(jti)
            logger.info("Security Event: Token JTI revoked", jti=jti)

    def is_revoked(self, jti: str | None) -> bool:
        """Checks if a JTI has been revoked."""
        if not jti:
            return False
        return jti in self.revoked_jtis

    async def get_jwks(self) -> dict[str, Any]:
        """Retrieves and caches JWKS keys from OIDC Issuer."""
        if "jwks" in self.jwks_cache:
            return self.jwks_cache["jwks"]

        jwks_url = f"{settings.OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/certs"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(jwks_url, timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    self.jwks_cache["jwks"] = data
                    return data
        except Exception as ex:
            logger.warning("Failed to fetch JWKS from IdP", url=jwks_url, error=str(ex))

        return {"keys": []}

    async def verify_token(self, token_str: str) -> SecurityContext:
        """Cryptographically verifies incoming token and returns normalized SecurityContext."""
        if not token_str:
            raise AuthenticationError("Missing Bearer access token")

        try:
            unverified_header = jwt.get_unverified_header(token_str)
            kid = unverified_header.get("kid")
            alg = unverified_header.get("alg", "RS256")

            # Check if this kid is a pre-registered test key
            key_to_use = None
            if kid and kid in self.test_public_keys:
                key_to_use = self.test_public_keys[kid]
            else:
                jwks = await self.get_jwks()
                for key_data in jwks.get("keys", []):
                    if key_data.get("kid") == kid:
                        key_to_use = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
                        break

            # If development environment and no key found, check for symmetric fallback only if explicitly dev
            if not key_to_use:
                if settings.ENVIRONMENT in ("development", "test") and "dev-secret" in self.test_public_keys:
                    key_to_use = self.test_public_keys["dev-secret"]
                else:
                    raise AuthenticationError(f"Unable to locate matching signing key for kid: {kid}")

            payload = jwt.decode(
                token_str,
                key=key_to_use,
                algorithms=[alg, "RS256", "ES256"],
                audience=settings.OIDC_AUDIENCE,
                issuer=settings.OIDC_ISSUER,
                options={"verify_exp": True, "verify_aud": True, "verify_iss": True}
            )

            # Check for token revocation (RFC 7662)
            jti = payload.get("jti")
            if jti and self.is_revoked(jti):
                raise AuthenticationError(f"Token with JTI '{jti}' has been revoked")

            context = SecurityContext.from_claims(payload, raw_token=token_str)
            return context

        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token signature has expired")
        except jwt.InvalidAudienceError:
            raise AuthenticationError(f"Invalid token audience (expected {settings.OIDC_AUDIENCE})")
        except jwt.InvalidIssuerError:
            raise AuthenticationError(f"Invalid token issuer (expected {settings.OIDC_ISSUER})")
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Token cryptographic verification failed: {e!s}")
        except Exception as e:
            raise AuthenticationError(f"Token decoding error: {e!s}")


oauth2_manager = OAuth21SecurityManager()


async def get_current_security_context(
    credentials: HTTPAuthorizationCredentials | None = Security(security_scheme)
) -> SecurityContext:
    """FastAPI dependency for extracting and verifying Bearer token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header with Bearer token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    try:
        return await oauth2_manager.verify_token(credentials.credentials)
    except AuthenticationError as auth_err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(auth_err),
            headers={"WWW-Authenticate": "Bearer"}
        )
