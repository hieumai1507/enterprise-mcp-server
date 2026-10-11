"""
Forensic Audit Trail & Integrity Verification Test Suite.
Verifies Section 6 of test_plan.md:
1. Cryptographic Payload Fingerprints (SHA-256)
2. PII Redaction in Stored Audit Payloads
3. Guardrail Traceability & Risk Score Logging
4. Zero State Leaks on Denials (No DB socket checked out)
"""

import json
from unittest.mock import patch

import pytest

from src.audit.buffer import audit_buffer
from src.audit.sanitizer import compute_payload_hash
from src.mcp.server import mcp_server


@pytest.mark.asyncio
async def test_audit_forensics_payload_hash_and_pii_masking(analyst_context):
    """
    Verifies Section 6.1 & 6.2:
    - Cryptographic SHA-256 fingerprint matches input
    - PII (credit cards) is masked before storage
    """
    sensitive_arguments = {
        "query": "SELECT id FROM users WHERE card = $1",
        "parameters": ["4111-2222-3333-4444"],
        "credit_card": "4111-2222-3333-4444"
    }

    res = await mcp_server.execute_tool(
        tool_name="read_query",
        arguments=sensitive_arguments,
        context=analyst_context,
        session_id="forensic-sess-01",
        client_ip="192.168.1.100"
    )

    assert res["isError"] is False

    # Retrieve last captured audit event from memory sink
    last_event = audit_buffer._memory_sink[-1]
    assert last_event["type"] == "tool_execution"
    assert last_event["actor_id"] == analyst_context.sub
    assert last_event["session_id"] == "forensic-sess-01"
    assert last_event["client_ip"] == "192.168.1.100"

    # 1. Assert Cryptographic SHA-256 Payload Fingerprint
    expected_hash = compute_payload_hash(sensitive_arguments)
    assert last_event["input_payload_hash"] == expected_hash

    # 2. Assert PII Masking: Raw credit card must NOT be present in stored audit arguments
    sanitized_args_str = json.dumps(last_event["sanitized_arguments"])
    assert "4111-2222-3333-4444" not in sanitized_args_str
    assert "****-****-****-****" in sanitized_args_str or "[REDACTED_SENSITIVE_FIELD]" in sanitized_args_str


@pytest.mark.asyncio
async def test_audit_forensics_guardrail_rejection_traceability(analyst_context):
    """
    Verifies Section 6.3:
    Audit records for JEV-blocked queries must record:
    - execution_status = 'GUARDRAIL_BLOCKED'
    - guardrail_evaluated = True
    - guardrail_risk_score >= 0.70
    - guardrail_decision = 'MALICIOUS_INJECTION'
    """
    adversarial_payload = {
        "query": "SELECT id FROM users UNION SELECT password FROM admin_credentials --",
        "parameters": []
    }

    res = await mcp_server.execute_tool(
        tool_name="read_query",
        arguments=adversarial_payload,
        context=analyst_context,
        session_id="forensic-sess-02"
    )

    assert res["isError"] is True
    assert res["errorCode"] == "GUARDRAIL_BLOCKED"

    # Inspect audit record
    last_event = audit_buffer._memory_sink[-1]
    assert last_event["execution_status"] == "GUARDRAIL_BLOCKED"
    assert last_event["guardrail_evaluated"] is True
    assert last_event["guardrail_risk_score"] >= 0.70
    assert last_event["guardrail_decision"] == "MALICIOUS_INJECTION"
    assert "TypeSafe AI JEV" in last_event["error_message"]


@pytest.mark.asyncio
async def test_audit_forensics_zero_state_leaks_on_rbac_denial(viewer_context):
    """
    Verifies Section 6.4:
    Confused Deputy & RBAC denial creates an audit trail without leaking DB connections.
    """
    with patch("src.db.session.db_manager.ro_pool") as mock_ro_pool:
        res = await mcp_server.execute_tool(
            tool_name="read_query",
            arguments={"query": "SELECT id FROM users", "parameters": []},
            context=viewer_context,
            session_id="forensic-sess-03"
        )

        assert res["isError"] is True
        assert res["errorCode"] == "FORBIDDEN"

        # Assert no DB socket acquired
        if mock_ro_pool:
            mock_ro_pool.acquire.assert_not_called()

        # Assert audit record captured denial
        last_event = audit_buffer._memory_sink[-1]
        assert last_event["execution_status"] == "AUTHORIZATION_DENIED"
        assert "Missing required OAuth scope" in last_event["error_message"]
