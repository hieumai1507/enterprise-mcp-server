# Enterprise PostgreSQL MCP Server

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![MCP](https://img.shields.io/badge/MCP-1.0-blueviolet.svg)](https://modelcontextprotocol.io/)
[![Security: OAuth 2.1](https://img.shields.io/badge/OAuth-2.1%20with%20PKCE-brightgreen.svg)](https://oauth.net/2.1/)
[![Guardrails: TypeSafe AI JEV](https://img.shields.io/badge/Guardrails-TypeSafe%20AI%20JEV-orange.svg)](https://typesafe.ai)

An open-source, hardened Model Context Protocol (MCP) server engineered as a secure, auditable Policy Enforcement Point (PEP) between Large Language Models (e.g., Anthropic Claude 3.5 Sonnet) and enterprise PostgreSQL databases.

---

## 1. Enterprise Architecture Overview

```
 [AI Agent / Orchestrator] 
           | (1) Authorization Code + PKCE
           v
 [Enterprise IdP (Keycloak / Okta)] ---> Issues RFC 9068 Scoped JWT
           |
           | (2) Bearer Token Handshake
           v
 +---------------------------------------------------------------+
 |            Enterprise PostgreSQL MCP Server (FastAPI)         |
 |                                                               |
 |  [OAuth 2.1 / PKCE Interceptor]                               |
 |          |                                                    |
 |          v                                                    |
 |  [Tool-Level RBAC Engine]                                     |
 |          |                                                    |
 |          v                                                    |
 |  [TypeSafe AI JEV Classifier-as-a-Judge Guardrail (< 50ms)]   |
 |          |                                                    |
 |          v                                                    |
 |  [SQL AST Validator & Parameterization]                       |
 |          |                                                    |
 |          +-----------------------+                            |
 |          |                       |                            |
 |          v                       v                            |
 |  [Async Audit Buffer]   [Isolated Service Pools]              |
 +----------|-----------------------|----------------------------+
            |                       |
            | (Append-Only DDL)     | (mcp_ro_service / mcp_rw_service)
            v                       v
    [Audit Tables]          [Enterprise DB Tables]
```

### Core Security Guarantees
1. **OAuth 2.1 with PKCE:** Mandatory S256 code challenge exchange, exact redirect URI matching, and asymmetric RS256/ES256 verification against OIDC JWKS.
2. **STRICTLY NO Token Passthrough:** Agent tokens terminate at the MCP boundary. All database queries execute across dedicated, least-privilege service connection pools (`mcp_ro_service` with transaction read-only, `mcp_rw_service`). Prevents **Confused Deputy Attacks** and connection pool starvation.
3. **Tool-Level RBAC:** Every tool requires explicit OAuth scopes and application realm roles. Destructive DDL (`drop_table`, `truncate_table`) is unconditionally prohibited for AI agents.
4. **Append-Only Tamper-Evident Audit Trail:** Non-blocking async queue records actor context, tool arguments, SHA-256 payload hashes, and execution status into monthly-partitioned tables.
5. **Real-Time AI Guardrails (TypeSafe AI JEV):** In-line Classifier-as-a-Judge inspects tool payloads for prompt injections, timing attacks, or exfiltration before hitting the database socket.

---

## 2. Directory Structure

```
enterprise-mcp-server/
├── config/
│   └── keycloak-realm-export.json        # Pre-configured Keycloak realm with PKCE
├── deploy/
│   └── scripts/
│       └── init-db.sh                    # Database roles & partitioned audit schema
├── src/
│   ├── main.py                           # Application bootstrap & ASGI lifespan
│   ├── core/
│   │   ├── config.py                     # Pydantic Settings
│   │   ├── exceptions.py                 # Structured security exception hierarchy
│   │   ├── rbac.py                       # Tool-level permission decider
│   │   ├── security.py                   # OAuth 2.1, PKCE & JWKS token verification
│   │   └── telemetry.py                  # Structured JSON logging via structlog
│   ├── db/
│   │   ├── query_builder.py              # SQL AST validation (sqlparse)
│   │   └── session.py                    # Multi-pool database manager (No Token Passthrough)
│   ├── audit/
│   │   ├── buffer.py                     # Asynchronous non-blocking audit queue
│   │   └── sanitizer.py                  # PII redactor (regex + SHA-256 hashes)
│   └── mcp/
│       ├── server.py                     # MCP protocol coordinator
│       ├── middleware/
│       │   └── guardrail_middleware.py   # TypeSafe AI JEV Classifier-as-a-Judge
│       ├── tools/
│       │   ├── registry.py               # Declarative tool registration
│       │   ├── database_schema.py        # list_tables, describe_table
│       │   ├── database_read.py          # read_query, execute_report
│       │   └── database_write.py         # update_record, insert_record
│       └── transport/
│           └── sse_endpoint.py           # MCP Server-Sent Events & JSON-RPC
├── tests/
│   ├── conftest.py                       # Ephemeral RSA keypairs & JWT generators
│   ├── unit/                             # Security, RBAC, Sanitizer & Audit unit tests
│   ├── integration/                      # MCP transport & database tool integration tests
│   └── security_evals/                   # AI-Driven JEV Classifier-as-a-Judge evals
├── Dockerfile                            # Multi-stage non-root container image
├── docker-compose.yml                    # Local dev topology (MCP + Postgres 16 + Keycloak)
└── pyproject.toml                        # PEP 621 dependencies & pytest configuration
```

---

## 3. Quickstart & Local Deployment

### Prerequisites
* Docker Engine 24+ & Docker Compose 2+
* Python 3.12+ (for local development)

### Launching with Docker Compose
To spin up the complete end-to-end zero-trust environment (PostgreSQL 16, Keycloak OIDC Provider, and the MCP Server):

```bash
docker compose up --build -d
```

### Healthcheck Verification
```bash
curl http://localhost:8000/health
```

Expected Response:
```json
{
  "status": "UP",
  "environment": "development",
  "database_pools": {
    "ro_pool": "healthy",
    "rw_pool": "healthy",
    "audit_pool": "healthy"
  },
  "audit_queue_size": 0,
  "guardrail_enabled": true
}
```

---

## 4. Running Tests & AI Evals

Execute the full 34-test suite including AI Guardrail evaluations:

```bash
# Run complete test suite with coverage
pytest -v --cov=src
```

### AI-Driven Evals with TypeSafe AI JEV
The test suite in [`tests/security_evals/test_jev_guardrails.py`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/tests/security_evals/test_jev_guardrails.py) evaluates real-time Classifier-as-a-Judge threat scores against benign queries and adversarial payloads:

```bash
pytest tests/security_evals/test_jev_guardrails.py -v
```

---

## 5. Architectural Documents

* [`solution_architecture.md`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/solution_architecture.md): System design, OAuth 2.1 PKCE sequence diagram, Confused Deputy mitigation, and PostgreSQL audit DDL.
* [`implementation_plan.md`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/implementation_plan.md): Architectural decisions and step-by-step implementation guide.
* [`test_plan.md`](file:///D:/PROJECTS/freelance-demo/Enterprise%20MCP%20Server/test_plan.md): Quality assurance matrix, security test vectors, and JEV evaluation criteria.
