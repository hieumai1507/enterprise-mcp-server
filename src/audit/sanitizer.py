"""
PII Sanitization and Cryptographic Payload Fingerprinting.
Masks sensitive information (PII, secrets) and calculates SHA-256 audit hashes.
"""

import hashlib
import json
import re
from typing import Any

# Regex patterns for sensitive data detection
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_REGEX = re.compile(r"\b(?:Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*|sk-[A-Za-z0-9]{20,})\b", re.IGNORECASE)
SENSITIVE_KEY_NAMES = {
    "password", "secret", "token", "access_token", "api_key",
    "authorization", "private_key", "credit_card", "ssn", "cvv"
}


def compute_payload_hash(payload: Any) -> str:
    """Computes a deterministic SHA-256 fingerprint of the input arguments."""
    try:
        serialized = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        serialized = str(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _sanitize_string(text: str) -> str:
    """Applies regex masking to sensitive substrings."""
    masked = CREDIT_CARD_REGEX.sub("****-****-****-****", text)
    masked = SSN_REGEX.sub("***-**-****", masked)
    masked = API_KEY_REGEX.sub("Bearer [REDACTED_SECRET]", masked)
    return masked


def sanitize_payload(obj: Any) -> Any:
    """
    Recursively inspects and sanitizes payload structures, redacting
    sensitive keys and masking PII values.
    """
    if isinstance(obj, dict):
        sanitized_dict = {}
        for k, v in obj.items():
            if any(sensitive in k.lower() for sensitive in SENSITIVE_KEY_NAMES):
                sanitized_dict[k] = "[REDACTED_SENSITIVE_FIELD]"
            else:
                sanitized_dict[k] = sanitize_payload(v)
        return sanitized_dict
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    elif isinstance(obj, str):
        return _sanitize_string(obj)
    return obj
