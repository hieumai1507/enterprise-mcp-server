# Enterprise PostgreSQL MCP Server: Implementation & Codebase Guide

**Author:** Lead Backend Engineer & AI Security Architect  
**Status:** Implemented & Verified in Production  
**Stack:** Python 3.12+ | FastAPI | Model Context Protocol (MCP) | PostgreSQL 16/17  

---

## 1. Architectural Decisions & Component Selection

| Component | Technology | Rationale & Practical Consideration |
| :--- | :--- | :--- |
| **Framework** | FastAPI (ASGI / Uvicorn) | High-throughput asynchronous request handling, native Pydantic v2 validation, and OpenAPI documentation. |
| **Protocol** | Model Context Protocol (`mcp`) | Server-Sent Events (SSE) and JSON-RPC 2.0 streaming transport for Claude and agent hosts. |
| **Authentication** | `PyJWT[crypto]` & `Authlib` | RFC 9068 JWT verification, JWKS key rotation cache (`TTLCache`), and RFC 7636 PKCE S256 verifier. |
| **Database Tier** | `asyncpg` + `pg8000` Fallback | High-performance async connection pooling on Linux, with pure-Python `pg8000` adapter when C-extensions are restricted. |
| **AI Guardrail** | TypeSafe AI JEV Classifier | In-line intent classification evaluating payload risk in $< 50\text{ ms}$ before database socket execution. |
| **Audit Buffer** | `asyncio.Queue` Worker | Bounded in-memory queue decoupling audit writes from tool latency. |

---

## 2. Codebase Organization

```
enterprise-mcp-server/
├── src/
│   ├── main.py                           # FastAPI lifespan & application bootstrap
│   ├── core/
│   │   ├── config.py                     # Pydantic Settings & environment variables
│   │   ├── security.py                   # OAuth 2.1, PKCE verification & JWKS cache
│   │   ├── rbac.py                       # Tool-level permission decider & decorators
│   │   ├── exceptions.py                 # Security exception hierarchy
│   │   └── telemetry.py                  # Structured JSON logging (structlog)
│   ├── db/
│   │   ├── session.py                    # Multi-pool database manager (RO, RW, Audit)
│   │   └── query_builder.py              # SQL AST validation (sqlparse)
│   ├── mcp/
│   │   ├── server.py                     # MCP server engine & tool dispatcher
│   │   ├── middleware/
│   │   │   └── guardrail_middleware.py   # TypeSafe AI JEV Classifier-as-a-Judge
│   │   ├── tools/                        # Modular tool registrations
│   │   │   ├── registry.py               # Declarative tool registry
│   │   │   ├── database_read.py          # read_query, execute_report
│   │   │   ├── database_schema.py        # list_tables, describe_table
│   │   │   └── database_write.py         # update_record, insert_record
│   │   └── transport/
│   │       └── sse_endpoint.py           # SSE handshake & JSON-RPC 2.0 broker
│   └── audit/
│       ├── buffer.py                     # Asynchronous non-blocking queue worker
│       └── sanitizer.py                  # PII redactor & SHA-256 parameter hashing
├── deploy/
│   ├── scripts/init.sql                  # PostgreSQL schema, roles & audit DDL
│   ├── kubernetes/deployment.yaml        # Production Kubernetes deployment manifests
│   └── clients/                          # Claude Desktop & Python SDK integration kits
├── scripts/
│   └── verify_live_e2e.py                # Live end-to-end verification harness
└── tests/                                # 37 automated unit, integration & eval tests
```

---

## 3. Core Implementation Highlights

### 3.1 Dual-Driver Database Manager ([`src/db/session.py`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/src/db/session.py))
PostgreSQL connection pooling provides isolated service credentials without passing client tokens down to the socket:

```python
class DatabaseManager:
    async def initialize(self) -> None:
        if asyncpg is not None:
            # High-performance asyncpg pool on standard Linux containers
            self.ro_pool = await asyncpg.create_pool(
                host=settings.DB_HOST, port=settings.DB_PORT, database=settings.DB_NAME,
                user=settings.DB_USER_RO, password=settings.DB_PASSWORD_RO,
                server_settings={"default_transaction_read_only": "on"}
            )
        elif pg8000 is not None:
            # Pure-Python fallback adapter for restricted C-extension environments
            self.ro_pool = PG8000PoolAdapter(
                user=settings.DB_USER_RO, password=settings.DB_PASSWORD_RO,
                host=settings.DB_HOST, port=settings.DB_PORT, database=settings.DB_NAME,
                is_read_only=True
            )
```

### 3.2 In-Line AI Guardrail Hook ([`src/mcp/server.py`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/src/mcp/server.py))
Every tool dispatch evaluates intent before checkout from the database connection pool:

```python
# 1. RBAC Scope & Role Enforcement
evaluate_rbac(context=context, required_scope=tool_def.required_scope, required_role=tool_def.required_role)

# 2. AI Semantic Intent Evaluation (TypeSafe AI JEV)
guardrail_result = await jev_guardrail.verify_and_gate(
    tool_name=tool_name, arguments=arguments, agent_context={"sub": context.sub}
)

# 3. Parameterized Execution (Only reached if Risk < 0.70)
result_payload = await tool_def.handler(arguments, security_context=context)
```

---

## 4. Production Deployment

### 4.1 Multi-Stage Hardened Dockerfile
The container runs as non-privileged user `10001` with minimal attack surface:

```bash
docker build -t enterprise-mcp-server:v1.0.0 .
docker run -p 8000:8000 --env-file .env enterprise-mcp-server:v1.0.0
```

### 4.2 Kubernetes Deployment
Apply manifests directly to the cluster:
```bash
kubectl apply -f deploy/kubernetes/deployment.yaml
```
