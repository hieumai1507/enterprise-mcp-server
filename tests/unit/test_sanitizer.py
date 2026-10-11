"""
Unit Tests for PII Masking and Audit Payload Fingerprinting.
"""

from src.audit.sanitizer import compute_payload_hash, sanitize_payload


def test_credit_card_masking():
    payload = {"user_query": "Check card 4111-2222-3333-4444 status"}
    sanitized = sanitize_payload(payload)
    assert "****-****-****-****" in sanitized["user_query"]
    assert "4111-2222-3333-4444" not in sanitized["user_query"]


def test_ssn_masking():
    payload = {"notes": "Customer SSN is 123-45-6789"}
    sanitized = sanitize_payload(payload)
    assert "***-**-****" in sanitized["notes"]
    assert "123-45-6789" not in sanitized["notes"]


def test_sensitive_keys_redaction():
    payload = {
        "username": "jdoe",
        "password": "MySuperSecretPassword123!",
        "access_token": "sk-12345678901234567890123456"
    }
    sanitized = sanitize_payload(payload)
    assert sanitized["username"] == "jdoe"
    assert sanitized["password"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["access_token"] == "[REDACTED_SENSITIVE_FIELD]"


def test_payload_hash_stability():
    """Validates deterministic SHA-256 fingerprinting regardless of key ordering."""
    payload1 = {"query": "SELECT 1", "limit": 10}
    payload2 = {"limit": 10, "query": "SELECT 1"}
    hash1 = compute_payload_hash(payload1)
    hash2 = compute_payload_hash(payload2)
    assert hash1 == hash2
    assert len(hash1) == 64
