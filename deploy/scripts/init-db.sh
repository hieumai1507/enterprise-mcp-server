#!/usr/bin/env bash
set -e

# ==============================================================================
# Enterprise PostgreSQL MCP Server - Database Bootstrap & Hardening Script
# ==============================================================================

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- 1. Create Dedicated Service Roles with Least Privilege
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mcp_ro_service') THEN
            CREATE ROLE mcp_ro_service WITH LOGIN PASSWORD 'ro_service_secret';
        END IF;

        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mcp_rw_service') THEN
            CREATE ROLE mcp_rw_service WITH LOGIN PASSWORD 'rw_service_secret';
        END IF;

        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mcp_audit_writer') THEN
            CREATE ROLE mcp_audit_writer WITH LOGIN PASSWORD 'audit_service_secret';
        END IF;
    END
    \$\$;

    -- 2. Setup Audit Schema & Extension
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    CREATE SCHEMA IF NOT EXISTS mcp_audit;

    -- Enum Types
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'execution_status') THEN
            CREATE TYPE mcp_audit.execution_status AS ENUM (
                'SUCCESS',
                'AUTHENTICATION_FAILED',
                'AUTHORIZATION_DENIED',
                'GUARDRAIL_BLOCKED',
                'VALIDATION_ERROR',
                'EXECUTION_ERROR',
                'TIMEOUT'
            );
        END IF;
    END
    \$\$;

    -- Audit Table (Partitioned by Month)
    CREATE TABLE IF NOT EXISTS mcp_audit.tool_execution_logs (
        event_id UUID DEFAULT gen_random_uuid(),
        event_timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        actor_id VARCHAR(255) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        session_id VARCHAR(255) NOT NULL,
        client_ip INET NOT NULL,
        tool_name VARCHAR(128) NOT NULL,
        granted_scopes TEXT[] NOT NULL,
        granted_roles TEXT[] NOT NULL,
        required_scope VARCHAR(128) NOT NULL,
        required_role VARCHAR(128) NOT NULL,
        input_payload_hash CHAR(64) NOT NULL,
        sanitized_arguments JSONB NOT NULL,
        guardrail_evaluated BOOLEAN NOT NULL DEFAULT FALSE,
        guardrail_risk_score NUMERIC(5, 4),
        guardrail_decision VARCHAR(64),
        execution_status VARCHAR(64) NOT NULL,
        db_service_account VARCHAR(64) NOT NULL,
        duration_ms NUMERIC(10, 3) NOT NULL,
        rows_affected INTEGER DEFAULT 0,
        error_message TEXT,
        PRIMARY KEY (event_timestamp, event_id)
    ) PARTITION BY RANGE (event_timestamp);

    -- Partitions for 2026/2027
    CREATE TABLE IF NOT EXISTS mcp_audit.tool_execution_logs_default 
        PARTITION OF mcp_audit.tool_execution_logs DEFAULT;

    -- Authorization Failures Table
    CREATE TABLE IF NOT EXISTS mcp_audit.authorization_failures (
        failure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        failure_timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        client_ip INET NOT NULL,
        claimed_sub VARCHAR(255),
        attempted_tool VARCHAR(128) NOT NULL,
        denial_reason TEXT NOT NULL,
        raw_headers JSONB
    );

    -- 3. Hardened Permission Grants on Audit Schema
    GRANT USAGE ON SCHEMA mcp_audit TO mcp_audit_writer;
    GRANT INSERT ON ALL TABLES IN SCHEMA mcp_audit TO mcp_audit_writer;
    REVOKE UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA mcp_audit FROM mcp_audit_writer;

    -- 4. Sample Business Tables (App Data)
    CREATE TABLE IF NOT EXISTS public.users (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        department VARCHAR(100) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT clock_timestamp()
    );

    CREATE TABLE IF NOT EXISTS public.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES public.users(id),
        total_amount NUMERIC(10, 2) NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMPTZ DEFAULT clock_timestamp()
    );

    -- Insert Sample Mock Data
    INSERT INTO public.users (full_name, email, department) VALUES
        ('Alice Chen', 'alice.chen@enterprise.internal', 'Engineering'),
        ('Bob Martinez', 'bob.martinez@enterprise.internal', 'Finance'),
        ('Carol Davis', 'carol.davis@enterprise.internal', 'Operations')
    ON CONFLICT (email) DO NOTHING;

    INSERT INTO public.orders (user_id, total_amount, status) VALUES
        (1, 1250.00, 'COMPLETED'),
        (2, 450.50, 'PENDING'),
        (3, 9800.00, 'COMPLETED')
    ON CONFLICT DO NOTHING;

    -- 5. Business Schema Permissions
    -- Read-Only service role
    GRANT USAGE ON SCHEMA public TO mcp_ro_service;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_ro_service;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_ro_service;

    -- Read-Write service role
    GRANT USAGE ON SCHEMA public TO mcp_rw_service;
    GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO mcp_rw_service;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_rw_service;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO mcp_rw_service;

EOSQL

echo "Enterprise PostgreSQL MCP Database initialized successfully."
