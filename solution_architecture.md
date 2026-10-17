# Enterprise PostgreSQL MCP Server: System Architecture & Threat Model

**Author:** Lead Backend Engineer & AI Security Architect  
**Status:** Production Baseline  
**Target:** Model Context Protocol (MCP) | FastAPI | PostgreSQL 16/17  

---

## 1. Problem Space & Threat Vectors

Deploying Large Language Models (LLMs) with database access introduces high-severity attack vectors:

1. **The Confused Deputy Attack:** An untrusted or prompt-injected agent operating on behalf of a low-privilege user executes unauthorized actions against downstream systems.
2. **Token Passthrough Vulnerability:** Propagating client/agent credentials directly to PostgreSQL destroys connection pooling, bypasses fine-grained tool policies, and risks credential leaks.
3. **Destructive DDL & Injection:** Unconstrained agents dynamically generating SQL statements that modify schemas or access credential tables.
4. **Auditability Gap:** Inability to correlate an agent's reasoning chain or tool call to an authenticated human/agent identity, executed SQL, and outcome.

This system functions as an **authenticating Policy Enforcement Point (PEP)** between LLMs and PostgreSQL.

---

## 2. High-Level Architecture

```mermaid
flowchart TD
    subgraph Client["AI Client Boundary"]
        Agent["AI Agent / LLM (Claude 3.5 / LangGraph)"]
    end

    subgraph Auth["Identity Provider Boundary"]
        IdP["Enterprise IdP (Okta / Azure AD / Keycloak)<br/>Issues RFC 9068 Scoped JWTs via PKCE"]
    end

    subgraph Gateway["Enterprise MCP Server (FastAPI)"]
        PEP["OAuth 2.1 & PKCE Interceptor"]
        RBAC["Tool-Level RBAC Decider"]
        JEV["TypeSafe AI JEV Guardrail (< 50ms)"]
        Parser["SQL AST Validator (sqlparse)"]
        AuditWorker["Async Audit Queue (asyncio.Queue)"]
    end

    subgraph Database["PostgreSQL 16/17 Database"]
        PoolRO[("Read-Only Pool: mcp_ro_service<br/>default_transaction_read_only = on")]
        PoolRW[("Read-Write Pool: mcp_rw_service<br/>Scoped DML Grants")]
        AuditDB[("Audit Schema: mcp_audit<br/>Owner: mcp_audit_writer (INSERT ONLY)")]
    end

    Agent -->|1. PKCE Auth| IdP
    Agent -->|2. MCP Request + Bearer JWT| PEP
    PEP -->|3. Cryptographic Validation| RBAC
    RBAC -->|4a. Deny (403)| AuditWorker
    RBAC -->|4b. Pass| JEV
    JEV -->|5a. Malicious Intent (Score >= 0.70)| AuditWorker
    JEV -->|5b. Safe Query| Parser
    Parser -->|6. Safe AST Execution| PoolRO
    Parser -->|6. Scoped Mutation| PoolRW
    AuditWorker -->|7. Non-blocking Flush| AuditDB
```

---

## 3. The "No Token Passthrough" Principle

### Why Token Passthrough is Prohibited
In naive MCP server implementations, client tokens are forwarded downstream to PostgreSQL (via OAuth-to-Kerberos exchange or custom DB proxies). This introduces critical failures:

| Dimension | Token Passthrough (Flawed) | No Token Passthrough (This Architecture) |
| :--- | :--- | :--- |
| **Authentication Boundary** | Identity leaks directly into database engine. | Token terminates at MCP server; DB is isolated. |
| **Connection Pooling** | Breaks connection pooling completely. Each token forces a new authenticated handshake. | Highly efficient pooling via `asyncpg` / `pg8000` with pre-allocated service connections. |
| **Least Privilege Enforcement** | Relies on database-native grants which lack LLM-specific context (tool parameters, intent). | Dual-layer security: MCP server validates tool RBAC and semantic intent before touching DB. |
| **Auditability** | DB logs only show generic identity without tool context or prompt parameters. | Full contextual audit: Links agent identity, tool arguments, intent risk score, and executed SQL. |
| **Credential Blast Radius** | Compromising an agent session grants direct network access to the PostgreSQL instance. | Agent has zero network access or credentials to the database; it can only invoke declared MCP tools. |

---

## 4. Tool-Level Role-Based Access Control (RBAC)

Every tool call must satisfy both **OAuth Scope** (protocol level) and **Application Realm Role** (domain level):

| MCP Tool Name | Description | Required OAuth Scope | Required Application Role | DB Service Account Used |
| :--- | :--- | :--- | :--- | :--- |
| `list_tables` | Lists accessible schemas and tables | `mcp:tools:schema` | `mcp_viewer` | `mcp_ro_service` |
| `describe_table` | Retrieves column types, keys, and indexes | `mcp:tools:schema` | `mcp_viewer` | `mcp_ro_service` |
| `read_query` | Executes parameterized `SELECT` queries | `mcp:tools:read` | `mcp_analyst_readonly` | `mcp_ro_service` |
| `execute_report` | Executes pre-approved analytical views | `mcp:tools:read` | `mcp_analyst_readonly` | `mcp_ro_service` |
| `update_record` | Updates targeted rows with explicit primary keys | `mcp:tools:write` | `mcp_operator_write` | `mcp_rw_service` |
| `insert_record` | Performs controlled single record inserts | `mcp:tools:write` | `mcp_operator_write` | `mcp_rw_service` |
| `drop_table` | Destructive DDL command | N/A | N/A | **Hard-Coded Blocked for AI** |

---

## 5. PostgreSQL Audit Subsystem (DDL)

Audit logs are written to an append-only, partitioned table in PostgreSQL. The `mcp_audit_writer` database role is strictly restricted to `INSERT` and `SELECT` operations; `UPDATE`, `DELETE`, and `TRUNCATE` are revoked at the database engine level.

```sql
CREATE SCHEMA IF NOT EXISTS mcp_audit;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Master Audit Table: Range Partitioned by Month
CREATE TABLE IF NOT EXISTS mcp_audit.tool_execution_logs (
    event_id UUID DEFAULT gen_random_uuid(),
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    actor_id VARCHAR(255) NOT NULL,              -- Token 'sub' claim
    client_id VARCHAR(255) NOT NULL,             -- Token 'client_id' claim
    session_id VARCHAR(255) NOT NULL,            -- MCP session identifier
    client_ip INET NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    granted_scopes TEXT[] NOT NULL,
    granted_roles TEXT[] NOT NULL,
    required_scope VARCHAR(128) NOT NULL,
    required_role VARCHAR(128) NOT NULL,
    input_payload_hash CHAR(64) NOT NULL,        -- SHA-256 fingerprint
    sanitized_arguments JSONB NOT NULL,          -- Arguments with PII masked
    guardrail_evaluated BOOLEAN NOT NULL DEFAULT FALSE,
    guardrail_risk_score NUMERIC(5, 4),          -- 0.0000 to 1.0000
    guardrail_decision VARCHAR(64),              -- 'SAFE' or 'MALICIOUS_INJECTION'
    execution_status VARCHAR(64) NOT NULL,       -- 'SUCCESS', 'GUARDRAIL_BLOCKED', etc.
    db_service_account VARCHAR(64) NOT NULL,     -- 'mcp_ro_service' or 'mcp_rw_service'
    duration_ms NUMERIC(10, 3) NOT NULL,
    rows_affected INTEGER DEFAULT 0,
    error_message TEXT,
    PRIMARY KEY (event_timestamp, event_id)
) PARTITION BY RANGE (event_timestamp);

-- Default Partition for Unpartitioned Ranges
CREATE TABLE IF NOT EXISTS mcp_audit.tool_execution_logs_default 
    PARTITION OF mcp_audit.tool_execution_logs DEFAULT;

-- Authorization Failures
CREATE TABLE IF NOT EXISTS mcp_audit.authorization_failures (
    failure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    failure_timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    client_ip INET NOT NULL,
    claimed_sub VARCHAR(255),
    attempted_tool VARCHAR(128) NOT NULL,
    denial_reason TEXT NOT NULL,
    raw_headers JSONB
);

-- Least Privilege Grants on Audit Schema
GRANT USAGE ON SCHEMA mcp_audit TO mcp_audit_writer;
GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA mcp_audit TO mcp_audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA mcp_audit FROM mcp_audit_writer;
```

---

## 6. Real-Time AI Intent Guardrail (TypeSafe AI JEV)

Before any parameterized query reaches PostgreSQL, an in-line middleware interceptor evaluates the semantic payload:

1. **Pre-Execution Evaluation (< 50ms):**
   * Computes risk score $S \in [0.0, 1.0]$.
   * Evaluates for SQL injection patterns (`UNION SELECT`, string-concatenated fragments), side-channel attacks (`pg_sleep`), and exfiltration attempts (`COPY TO PROGRAM`).
2. **Gating Logic:**
   * If $S \ge 0.70$: Execution is immediately halted with `GuardrailViolationError` (errorCode: `GUARDRAIL_BLOCKED`).
   * **Zero database connections are acquired**, preventing any query execution or timing side-channels.
   * A high-severity audit record is dispatched to `mcp_audit.tool_execution_logs`.
