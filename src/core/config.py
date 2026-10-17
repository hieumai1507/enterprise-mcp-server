"""
Configuration Management for Enterprise PostgreSQL MCP Server.
Utilizes Pydantic Settings for strictly validated runtime configurations.
"""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    ENVIRONMENT: str = Field(default="production", description="Environment tier: production, staging, development, test")
    SERVER_HOST: str = Field(default="0.0.0.0", description="FastAPI host binding")
    SERVER_PORT: int = Field(default=8000, description="FastAPI port binding")
    DEBUG: bool = Field(default=False, description="Debug mode flag")

    # OAuth 2.1 & OIDC Configuration
    OIDC_ISSUER: str = Field(
        default="http://localhost:8080/realms/ai-services",
        description="OIDC Issuer URL (e.g., Keycloak realm or Okta domain)"
    )
    OIDC_AUDIENCE: str = Field(
        default="mcp-postgres-server",
        description="Expected audience ('aud') claim in incoming JWTs"
    )
    OIDC_JWKS_CACHE_TTL_SECONDS: int = Field(
        default=3600,
        description="TTL for caching IdP JWKS public keys in seconds"
    )

    # Isolated PostgreSQL Service Accounts (Strictly NO Token Passthrough)
    DB_HOST: str = Field(default="localhost", description="PostgreSQL host")
    DB_PORT: int = Field(default=5432, description="PostgreSQL port")
    DB_NAME: str = Field(default="enterprise_db", description="PostgreSQL database name")

    # 1. Read-Only Service Account (SELECT queries only)
    DB_USER_RO: str = Field(default="mcp_ro_service", description="Read-only PostgreSQL username")
    DB_PASSWORD_RO: str = Field(default="ro_service_secret", description="Read-only PostgreSQL password")

    # 2. Read-Write Service Account (Targeted DML)
    DB_USER_RW: str = Field(default="mcp_rw_service", description="Read-write PostgreSQL username")
    DB_PASSWORD_RW: str = Field(default="rw_service_secret", description="Read-write PostgreSQL password")

    # 3. Audit Logging Service Account (Append-only mcp_audit table writer)
    DB_USER_AUDIT: str = Field(default="mcp_audit_writer", description="Audit writer PostgreSQL username")
    DB_PASSWORD_AUDIT: str = Field(default="audit_service_secret", description="Audit writer PostgreSQL password")

    # Connection Pool Performance Tuning
    DB_POOL_MIN_SIZE: int = Field(default=2, description="Minimum pool connections per tier")
    DB_POOL_MAX_SIZE: int = Field(default=10, description="Maximum pool connections per tier")
    DB_POOL_TIMEOUT_SECONDS: float = Field(default=10.0, description="Command execution timeout in seconds")
    DB_STATEMENT_TIMEOUT_MS: int = Field(default=3000, description="PostgreSQL statement_timeout in milliseconds (DoS cutoff)")

    # Query Governor & Table Access Control
    QUERY_DEFAULT_LIMIT: int = Field(default=100, description="Default LIMIT injected if missing in SELECT queries")
    QUERY_MAX_ROWS: int = Field(default=1000, description="Maximum allowed rows in memory to prevent OOM")
    ALLOWED_TABLES: list[str] = Field(
        default=["users", "orders", "products", "departments"],
        description="Explicit table allowlist for agent read queries"
    )
    DENIED_TABLES: list[str] = Field(
        default=["salaries", "credentials", "api_keys", "system_secrets", "pg_authid", "pg_shadow"],
        description="Prohibited tables blocked regardless of queries"
    )

    # AI Guardrail: TypeSafe AI JEV Model Configuration
    JEV_MODEL_ENDPOINT: str | None = Field(
        default="https://api.typesafe.ai/v1/jev",
        description="TypeSafe AI JEV Classifier API endpoint"
    )
    JEV_API_KEY: str | None = Field(
        default="mock-jev-api-key",
        description="API Key for TypeSafe AI JEV inference"
    )
    JEV_RISK_THRESHOLD: float = Field(
        default=0.70,
        description="Threshold [0.0 - 1.0] above which queries are blocked as malicious"
    )
    JEV_ENABLED: bool = Field(
        default=True,
        description="Flag to toggle real-time JEV intent guardrail evaluation"
    )

    # Durable Write-Ahead Log (WAL) Audit Storage
    AUDIT_WAL_PATH: str = Field(
        default="audit_wal.db",
        description="Path to SQLite durable Write-Ahead Log (WAL) on disk"
    )
    AUDIT_QUEUE_SIZE: int = Field(
        default=10000,
        description="Maximum capacity of in-memory async audit queue"
    )
    AUDIT_FAIL_CLOSED: bool = Field(
        default=False,
        description="If True, reject operations when audit buffer overflows or DB writer fails"
    )


settings = Settings()
