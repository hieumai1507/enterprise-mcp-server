# Enterprise PostgreSQL MCP Server: Implementation Plan

**Document Version:** 1.0.0  
**Target Runtime:** Python 3.12+ | FastAPI 0.115+ | MCP Python SDK 1.0+ | PostgreSQL 16+  
**Architecture Pattern:** Clean Hexagonal Architecture / Zero-Trust Policy Enforcement Point (PEP)  

---

## 1. Technology Stack & Architectural Decision Records (ADRs)

| Component | Technology Selected | Rationale & Trade-off Analysis |
| :--- | :--- | :--- |
| **Language Runtime** | Python 3.12+ | Asyncio performance improvements, improved typing syntax, native sub-interpreter support, and ecosystem compatibility with AI toolsets. |
| **Web Framework** | FastAPI (ASGI / Uvicorn) | High-throughput asynchronous request handling, declarative dependency injection for security contexts, and native Pydantic v2 integration. |
| **MCP Protocol Layer** | Official MCP Python SDK (`mcp`) | Standard-compliant implementation of the Model Context Protocol over Server-Sent Events (SSE) and stdio transports. |
| **Authentication & OIDC** | `Authlib` & `PyJWT[crypto]` | RFC 9068-compliant JWT verification, automated JWKS key rotation handling via cached HTTP client, and cryptographic PKCE utilities. |
| **Data Validation** | `Pydantic v2` & `pydantic-settings` | Rust-backed blazing-fast validation, strict type coercion prevention, sensitive field masking, and schema export. |
| **Database Driver** | `asyncpg` + `SQLAlchemy 2.0` (Async) | `asyncpg` offers the lowest latency PostgreSQL driver in Python. SQLAlchemy Core provides safe dynamic query building without ORM overhead. |
| **Structured Logging** | `structlog` | High-performance, zero-allocation structured JSON logging compatible with OpenTelemetry and Datadog/Splunk formatters. |
| **Async Worker Queue** | `asyncio.Queue` (Internal Worker) | Zero-external-dependency asynchronous buffer for decoupling audit log persistence from client-facing tool response latency. |

---

## 2. Production Codebase Directory Layout

```
enterprise-mcp-server/
├── .dockerignore
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── README.md
├── alembic.ini
├── migrations/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 001_initial_audit_and_app_schema.py
├── config/
│   └── keycloak-realm-export.json        # Pre-configured OAuth 2.1 realm
├── deploy/
│   ├── kubernetes/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── ingress.yaml
│   └── scripts/
│       └── init-db.sh                    # DB bootstrap with roles & privileges
├── src/
│   ├── __init__.py
│   ├── main.py                           # Application bootstrap & ASGI entrypoint
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py                     # Pydantic Settings & environment variables
│   │   ├── security.py                   # OAuth 2.1, JWKS validator & PKCE verification
│   │   ├── rbac.py                       # Tool-level permission decider & decorators
│   │   ├── exceptions.py                 # Domain & security exception hierarchies
│   │   └── telemetry.py                  # OpenTelemetry & structlog initialization
│   ├── db/
│   │   ├── __init__.py
│   │   ├── session.py                    # Multi-pool database manager (RO, RW, Audit)
│   │   └── query_builder.py              # Safe parameterized query builder & AST sanity
│   ├── mcp/
│   │   ├── __init__.py
│   │   ├── server.py                     # MCP Server instance & lifecycle hooks
│   │   ├── transport/
│   │   │   ├── __init__.py
│   │   │   └── sse_endpoint.py           # FastAPI SSE route handlers & session tracking
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── auth_middleware.py        # Token inspection & context injection
│   │   │   └── guardrail_middleware.py   # AI intent evaluation interceptor
│   │   └── tools/
│   │       ├── __init__.py
│   │       ├── registry.py               # Declarative tool registry & metadata
│   │       ├── database_schema.py        # list_tables, describe_table
│   │       ├── database_read.py          # read_query, execute_report
│   │       └── database_write.py         # update_record, insert_record
│   └── audit/
│       ├── __init__.py
│       ├── buffer.py                     # Async queue buffer & worker task
│       ├── writer.py                     # Bulk audit log repository
│       └── sanitizer.py                  # PII redactor (regex + hash masks)
└── tests/
    ├── conftest.py                       # Pytest fixtures & mock IdP / testcontainers
    ├── unit/
    │   ├── test_security.py
    │   ├── test_rbac.py
    │   └── test_sanitizer.py
    ├── integration/
    │   ├── test_mcp_sse_transport.py
    │   ├── test_database_tools.py
    │   └── test_audit_pipeline.py
    └── security_evals/
        ├── test_jev_guardrails.py        # AI-driven classifier-as-a-judge test suite
        └── payloads/                     # Malicious & benign evaluation datasets
```

---

## 3. Step-by-Step Implementation Phases

### Phase 1: Environment, Configuration & Dependency Architecture

#### `pyproject.toml`
Defines strict dependency pinning using modern PEP 621 standards:

```toml
[project]
name = "enterprise-postgresql-mcp-server"
version = "1.0.0"
description = "Hardened, enterprise-grade Model Context Protocol server for PostgreSQL with OAuth 2.1, RBAC, and AI Guardrails"
authors = [{ name = "Enterprise Architecture Team", email = "sec-eng@enterprise.internal" }]
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "mcp>=1.0.0",
    "authlib>=1.3.1",
    "pyjwt[crypto]>=2.9.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.5.0",
    "asyncpg>=0.29.0",
    "sqlalchemy[asyncio]>=2.0.35",
    "structlog>=24.4.0",
    "cachetools>=5.5.0",
    "sqlparse>=0.5.1",
    "httpx>=0.27.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "testcontainers[postgres]>=4.8.0",
    "coverage>=7.6.0",
    "ruff>=0.6.0",
    "mypy>=1.11.0"
]
```

#### `src/core/config.py`
Enforces validated environment configuration via Pydantic:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, PostgresDsn, Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True)

    ENVIRONMENT: str = Field(default="production")
    SERVER_HOST: str = Field(default="0.0.0.0")
    SERVER_PORT: int = Field(default=8000)

    # OAuth 2.1 / OIDC Provider
    OIDC_ISSUER: AnyHttpUrl = Field(description="OIDC Issuer URL (e.g. Keycloak realm)")
    OIDC_AUDIENCE: str = Field(default="mcp-postgres-server")
    OIDC_JWKS_CACHE_TTL_SECONDS: int = Field(default=3600)

    # Isolated Database Service Account Connections (Strictly No Token Passthrough)
    DB_HOST: str
    DB_PORT: int = 5432
    DB_NAME: str
    
    # Read-Only Service Account
    DB_USER_RO: str = "mcp_ro_service"
    DB_PASSWORD_RO: str
    
    # Read-Write Service Account
    DB_USER_RW: str = "mcp_rw_service"
    DB_PASSWORD_RW: str
    
    # Audit Logger Service Account
    DB_USER_AUDIT: str = "mcp_audit_writer"
    DB_PASSWORD_AUDIT: str

    # Pool Configurations
    DB_POOL_MIN_SIZE: int = 5
    DB_POOL_MAX_SIZE: int = 20
    DB_POOL_TIMEOUT_SECONDS: float = 10.0

    # Guardrail Configuration (JEV Classifier)
    JEV_MODEL_ENDPOINT: AnyHttpUrl | None = None
    JEV_API_KEY: str | None = None
    JEV_RISK_THRESHOLD: float = 0.70  # Deny queries with risk score >= 0.70

settings = Settings()
```

---

### Phase 2: Dual Database Connection Pooling & Credentials Isolation

The server establishes isolated connection pools for distinct security tiers using `asyncpg`. This implements the **"No Token Passthrough"** requirement at the socket layer.

#### `src/db/session.py`

```python
import asyncpg
from typing import Optional
from src.core.config import settings
import structlog

logger = structlog.get_logger(__name__)

class DatabaseManager:
    """
    Manages isolated asyncpg connection pools for each privilege tier.
    Zero client tokens are forwarded to PostgreSQL.
    """
    def __init__(self):
        self.ro_pool: Optional[asyncpg.Pool] = None
        self.rw_pool: Optional[asyncpg.Pool] = None
        self.audit_pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        logger.info("Initializing isolated database connection pools...")
        
        # Read-Only Pool (SELECT only)
        self.ro_pool = await asyncpg.create_pool(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            database=settings.DB_NAME,
            user=settings.DB_USER_RO,
            password=settings.DB_PASSWORD_RO,
            min_size=settings.DB_POOL_MIN_SIZE,
            max_size=settings.DB_POOL_MAX_SIZE,
            command_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
            server_settings={"default_transaction_read_only": "on"}
        )

        # Read-Write Pool (Targeted DML)
        self.rw_pool = await asyncpg.create_pool(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            database=settings.DB_NAME,
            user=settings.DB_USER_RW,
            password=settings.DB_PASSWORD_RW,
            min_size=2,
            max_size=settings.DB_POOL_MAX_SIZE,
            command_timeout=settings.DB_POOL_TIMEOUT_SECONDS
        )

        # Audit Logging Pool (Append-only writer)
        self.audit_pool = await asyncpg.create_pool(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            database=settings.DB_NAME,
            user=settings.DB_USER_AUDIT,
            password=settings.DB_PASSWORD_AUDIT,
            min_size=2,
            max_size=10
        )
        logger.info("All connection pools successfully established.")

    async def close(self) -> None:
        if self.ro_pool: await self.ro_pool.close()
        if self.rw_pool: await self.rw_pool.close()
        if self.audit_pool: await self.audit_pool.close()

db_manager = DatabaseManager()
```

---

### Phase 3: OAuth 2.1 & PKCE Token Verification Engine

This component intercepts every MCP incoming connection/request, validating the cryptographic JWT without relying on downstream services.

#### `src/core/security.py`

```python
import jwt
import httpx
from cachetools import TTLCache
from typing import Dict, Any
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.core.config import settings
import structlog

logger = structlog.get_logger(__name__)
security_bearer = HTTPBearer(auto_error=False)

class OAuth21SecurityManager:
    def __init__(self):
        self.jwks_cache = TTLCache(maxsize=10, ttl=settings.OIDC_JWKS_CACHE_TTL_SECONDS)
        self.jwks_url = f"{str(settings.OIDC_ISSUER).rstrip('/')}/protocol/openid-connect/certs"

    async def get_jwks(self) -> Dict[str, Any]:
        if "jwks" in self.jwks_cache:
            return self.jwks_cache["jwks"]
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.jwks_url, timeout=5.0)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Failed to retrieve IdP JWKS public keys")
            jwks = resp.json()
            self.jwks_cache["jwks"] = jwks
            return jwks

    async def verify_token(self, credentials: HTTPAuthorizationCredentials | None) -> Dict[str, Any]:
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer access token"
            )

        token = credentials.credentials
        try:
            jwks = await self.get_jwks()
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
                    break

            if not rsa_key:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unable to locate matching JWKS key")

            payload = jwt.decode(
                token,
                key=jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key),
                algorithms=["RS256", "ES256"],
                audience=settings.OIDC_AUDIENCE,
                issuer=str(settings.OIDC_ISSUER)
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token signature expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}")

oauth2_security = OAuth21SecurityManager()
```

---

### Phase 4: Declarative Tool RBAC Decorator & Security Interceptor

Tools declare required OAuth scopes and functional application roles. A decorator inspects the validated context prior to tool dispatch.

#### `src/core/rbac.py`

```python
from functools import wraps
from typing import Callable, List, Dict, Any
from src.core.exceptions import InsufficientPermissionsError
import structlog

logger = structlog.get_logger(__name__)

def require_permissions(required_scope: str, required_role: str):
    """
    Declarative decorator for MCP tool endpoints enforcing Scope and Role requirements.
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            security_context: Dict[str, Any] = kwargs.get("security_context", {})
            if not security_context:
                raise InsufficientPermissionsError("Unauthenticated context provided to tool")

            # Check OAuth Scope
            token_scopes: List[str] = security_context.get("scope", "").split()
            if required_scope not in token_scopes:
                logger.warn("RBAC Denied: Missing Scope", 
                            actor=security_context.get("sub"), 
                            required=required_scope, 
                            granted=token_scopes)
                raise InsufficientPermissionsError(f"Missing required OAuth scope: {required_scope}")

            # Check Application Role
            realm_access = security_context.get("realm_access", {})
            token_roles: List[str] = realm_access.get("roles", [])
            if required_role not in token_roles:
                logger.warn("RBAC Denied: Missing Role", 
                            actor=security_context.get("sub"), 
                            required=required_role, 
                            granted=token_roles)
                raise InsufficientPermissionsError(f"Missing required application role: {required_role}")

            return await func(*args, **kwargs)
        
        # Attach permission metadata for self-documenting MCP schema discovery
        wrapper._required_scope = required_scope
        wrapper._required_role = required_role
        return wrapper
    return decorator
```

---

### Phase 5: High-Performance Parameterized Tool Implementation

Tool handlers accept structured Pydantic parameters, preventing raw string concatenation and enforcing SQL safety.

#### `src/mcp/tools/database_read.py`

```python
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from src.core.rbac import require_permissions
from src.db.session import db_manager
import sqlparse

class ReadQueryInput(BaseModel):
    query: str = Field(description="Parameterized SELECT SQL query")
    parameters: List[Any] = Field(default_factory=list, description="Positional query parameters ($1, $2, ...)")

@require_permissions(required_scope="mcp:tools:read", required_role="mcp_analyst_readonly")
async def execute_read_query(payload: ReadQueryInput, security_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    # AST Structural Sanity Check
    parsed = sqlparse.parse(payload.query)
    if not parsed:
        raise ValueError("Invalid SQL statement")
    
    statement = parsed[0]
    if statement.get_type() != "SELECT":
        raise PermissionError(f"Prohibited SQL statement type: {statement.get_type()}. Only SELECT statements permitted.")

    # Execute against Read-Only Service Account Pool
    async with db_manager.ro_pool.acquire() as conn:
        records = await conn.fetch(payload.query, *payload.parameters)
        return [dict(rec) for rec in records]
```

---

### Phase 6: Asynchronous Non-Blocking Audit Subsystem

To eliminate tool latency, the audit subsystem utilizes an in-memory `asyncio.Queue` consumed by a resilient background worker.

#### `src/audit/buffer.py`

```python
import asyncio
import json
import hashlib
from typing import Dict, Any
from src.core.config import settings
from src.db.session import db_manager
from src.audit.sanitizer import sanitize_payload
import structlog

logger = structlog.get_logger(__name__)

class AuditBuffer:
    def __init__(self, queue_size: int = 10000):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.worker_task: asyncio.Task | None = None
        self.running: bool = False

    async def start(self):
        self.running = True
        self.worker_task = asyncio.create_task(self._process_queue())
        logger.info("Audit buffer worker task started.")

    async def stop(self):
        self.running = False
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass

    async def emit_log(self, event: Dict[str, Any]):
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit queue is full! Potential backpressure or database stall.")
            # In fail-closed high security mode, raise an exception or write to fallback disk buffer

    async def _process_queue(self):
        while self.running:
            try:
                event = await self.queue.get()
                await self._persist_event(event)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Failed to persist audit log", error=str(e))
                await asyncio.sleep(0.5)

    async def _persist_event(self, event: Dict[str, Any]):
        raw_args_json = json.dumps(event.get("arguments", {}), sort_keys=True)
        payload_hash = hashlib.sha256(raw_args_json.encode()).hexdigest()
        sanitized_args = sanitize_payload(event.get("arguments", {}))

        insert_sql = """
            INSERT INTO mcp_audit.tool_execution_logs (
                actor_id, client_id, session_id, client_ip, tool_name,
                granted_scopes, granted_roles, required_scope, required_role,
                input_payload_hash, sanitized_arguments, guardrail_evaluated,
                guardrail_risk_score, guardrail_decision, execution_status,
                db_service_account, duration_ms, rows_affected
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
        """
        async with db_manager.audit_pool.acquire() as conn:
            await conn.execute(
                insert_sql,
                event["actor_id"],
                event["client_id"],
                event["session_id"],
                event["client_ip"],
                event["tool_name"],
                event["granted_scopes"],
                event["granted_roles"],
                event["required_scope"],
                event["required_role"],
                payload_hash,
                json.dumps(sanitized_args),
                event.get("guardrail_evaluated", False),
                event.get("guardrail_risk_score"),
                event.get("guardrail_decision"),
                event["execution_status"],
                event["db_service_account"],
                event["duration_ms"],
                event.get("rows_affected", 0)
            )

audit_buffer = AuditBuffer()
```

---

## 4. Production Containerization & Deployment

### 4.1 Multi-Stage Hardened Dockerfile

Implements a non-root, minimal attack-surface container image:

```dockerfile
# Stage 1: Build & Dependency Resolution
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Minimal Runtime
FROM python:3.12-slim-bookworm AS runner

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install only runtime postgres library
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-privileged user and group
RUN groupadd -g 10001 mcpuser && \
    useradd -u 10001 -g mcpuser -s /sbin/nologin -d /app mcpuser

# Copy installed wheels and binaries from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ /app/src/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/

RUN chown -R mcpuser:mcpuser /app
USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers"]
```

### 4.2 Local Orchestration Stack: `docker-compose.yml`

Deploys the complete zero-trust testing topology: MCP Server, PostgreSQL 16, and Keycloak Identity Provider:

```yaml
version: "3.9"

services:
  keycloak:
    image: quay.io/keycloak/keycloak:25.0
    container_name: enterprise-mcp-keycloak
    command: start-dev --import-realm
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin_password
    volumes:
      - ./config/keycloak-realm-export.json:/opt/keycloak/data/import/realm.json:ro
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/8080; echo -e 'GET /health/ready HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n' >&3; cat <&3 | grep -q '200 OK'"]
      interval: 10s
      timeout: 5s
      retries: 5

  postgres:
    image: postgres:16-alpine
    container_name: enterprise-mcp-postgres
    environment:
      POSTGRES_DB: enterprise_db
      POSTGRES_USER: postgres_admin
      POSTGRES_PASSWORD: admin_master_password
    volumes:
      - ./deploy/scripts/init-db.sh:/docker-entrypoint-initdb.d/init-db.sh:ro
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres_admin -d enterprise_db"]
      interval: 5s
      timeout: 5s
      retries: 5

  mcp-server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: enterprise-mcp-server
    environment:
      ENVIRONMENT: development
      OIDC_ISSUER: http://keycloak:8080/realms/ai-services
      OIDC_AUDIENCE: mcp-postgres-server
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: enterprise_db
      DB_USER_RO: mcp_ro_service
      DB_PASSWORD_RO: ro_service_secret
      DB_USER_RW: mcp_rw_service
      DB_PASSWORD_RW: rw_service_secret
      DB_USER_AUDIT: mcp_audit_writer
      DB_PASSWORD_AUDIT: audit_service_secret
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      keycloak:
        condition: service_healthy

volumes:
  pgdata:
```
