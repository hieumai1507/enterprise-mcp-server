"""
AI-Driven Intent Guardrail using TypeSafe AI JEV Model.
Classifier-as-a-Judge real-time semantic evaluation of tool payloads before DB execution.
"""

import re
import time
from typing import Any

import httpx
import structlog

from src.core.config import settings
from src.core.exceptions import GuardrailViolationError

logger = structlog.get_logger(__name__)

# Pre-compiled high-speed regex threat patterns for sub-millisecond evaluation
THREAT_VECTORS = [
    (
        "RCE_EXFILTRATION",
        re.compile(r"\bcopy\b[\s\S]*?\b(?:to|from)\s+program\b|\b(?:curl|wget)\b|\blo_(?:import|export)\b|\bpg_read_file\b|\bpg_write_file\b", re.IGNORECASE),
        0.99,
        "Remote code execution or out-of-band file exfiltration vector detected"
    ),
    (
        "SQL_INJECTION",
        re.compile(r"\bunion\b[\s\S]*?\bselect\b|\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|;\s*(?:drop|truncate|alter|create|insert|update|delete|grant|revoke)\b", re.IGNORECASE),
        0.98,
        "SQL injection syntax (UNION probe, tautology, or stacked query) detected"
    ),
    (
        "SIDE_CHANNEL_TIMING",
        re.compile(r"\bpg_sleep\s*\(|\bpg_sleep_for\s*\(|\bpg_sleep_until\s*\(|\bwaitfor\s+delay\b|\bbenchmark\s*\(", re.IGNORECASE),
        0.95,
        "Blind side-channel timing attack pattern detected"
    ),
    (
        "CATALOG_RECONNAISSANCE",
        re.compile(r"\binformation_schema\.(?:tables|columns|schemata|routines|views)\b|\bpg_catalog\b|\bpg_(?:class|database|tables|roles|user|shadow|authid|stat_activity|proc|settings)\b|\bcurrent_setting\s*\(", re.IGNORECASE),
        0.92,
        "Internal database catalog reconnaissance or credential table probing detected"
    ),
    (
        "DATA_DESTRUCTION",
        re.compile(r"\b(?:drop\s+table|drop\s+database|truncate\s+table)\b", re.IGNORECASE),
        0.99,
        "Destructive DDL statement prohibited in analytical queries"
    ),
    (
        "CREDENTIAL_HARVESTING",
        re.compile(r"\badmin_credentials\b|\bsystem_secrets\b|\bapi_keys\b|\bpg_shadow\b|\bpg_authid\b", re.IGNORECASE),
        0.99,
        "Direct credential harvesting target detected"
    )
]


def normalize_sql_payload(raw_text: str) -> str:
    """
    Normalizes SQL payload to defeat comment evasion and whitespace obfuscation.
    Strips inline /* ... */ and line -- comments, unescapes, and collapses whitespace.
    """
    # 1. Strip multi-line comments: /* ... */
    cleaned = re.sub(r"/\*.*?\*/", " ", raw_text, flags=re.DOTALL)
    # 2. Strip single-line comments: -- ...
    cleaned = re.sub(r"--.*?$", " ", cleaned, flags=re.MULTILINE)
    # 3. Collapse multiple whitespace characters into single space
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


class JevClassifierGuardrail:
    """
    Client for TypeSafe AI JEV Classifier-as-a-Judge.
    Evaluates semantic payloads and computes risk scores in < 50ms.
    """
    def __init__(
        self,
        endpoint: str | None = settings.JEV_MODEL_ENDPOINT,
        api_key: str | None = settings.JEV_API_KEY,
        risk_threshold: float = settings.JEV_RISK_THRESHOLD
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.risk_threshold = risk_threshold

    async def evaluate_payload(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Classifies incoming tool payload.
        Returns:
            {
                "risk_score": float,       # 0.00 to 1.00
                "classification": str,     # 'SAFE', 'MALICIOUS_INJECTION'
                "threat_type": str,        # 'SQL_INJECTION', 'CATALOG_RECONNAISSANCE', etc.
                "reason": str,
                "latency_ms": float
            }
        """
        if not settings.JEV_ENABLED:
            return {
                "risk_score": 0.0,
                "classification": "SAFE",
                "threat_type": "NONE",
                "reason": "Guardrail disabled by configuration",
                "latency_ms": 0.0
            }

        start_time = time.perf_counter()

        # In production with live API endpoint configured, dispatch HTTP request
        if self.endpoint and self.api_key and "mock" not in self.api_key:
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "agent_context": agent_context
                }
                async with httpx.AsyncClient(timeout=0.1) as client:
                    resp = await client.post(self.endpoint, json=payload, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        latency = (time.perf_counter() - start_time) * 1000
                        data["latency_ms"] = latency
                        return data
            except Exception as ex:
                logger.warning("Remote JEV endpoint unreachable, falling back to embedded engine", error=str(ex))

        # Embedded high-speed classification engine for development and local testing
        latency = (time.perf_counter() - start_time) * 1000
        classification, risk_score, threat_type, reason = self._embedded_classify(tool_name, arguments)

        return {
            "risk_score": risk_score,
            "classification": classification,
            "threat_type": threat_type,
            "reason": reason,
            "latency_ms": latency
        }

    def _embedded_classify(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, float, str, str]:
        """
        Embedded high-speed classifier with comment normalization and multi-vector threat matching.
        Evaluates in < 1ms to satisfy strict sub-50ms latency SLAs.
        """
        # Extract query text or serialize arguments
        raw_query = arguments.get("query") if isinstance(arguments, dict) else ""
        if not raw_query:
            raw_query = str(arguments)

        normalized = normalize_sql_payload(raw_query)

        # Multi-vector regex scan over normalized payload
        for threat_type, pattern, risk_score, reason in THREAT_VECTORS:
            if pattern.search(normalized) or pattern.search(str(arguments)):
                return (
                    "MALICIOUS_INJECTION",
                    risk_score,
                    threat_type,
                    f"[{threat_type}] {reason}"
                )

        return (
            "SAFE",
            0.02,
            "NONE",
            "Query intent classified as benign parameterized operation"
        )

    async def verify_and_gate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Executes JEV evaluation and raises GuardrailViolationError if risk exceeds threshold.
        """
        result = await self.evaluate_payload(tool_name, arguments, agent_context)
        if result["risk_score"] >= self.risk_threshold:
            logger.critical(
                "Guardrail Alert: Malicious tool payload blocked by TypeSafe AI JEV",
                tool=tool_name,
                risk_score=result["risk_score"],
                classification=result["classification"],
                threat_type=result.get("threat_type", "UNKNOWN"),
                reason=result["reason"]
            )
            raise GuardrailViolationError(
                f"Blocked by TypeSafe AI JEV Guardrail: {result['classification']} (Score: {result['risk_score']:.2f}) - {result['reason']}",
                risk_score=result["risk_score"],
                classification=result["classification"],
                reason=result["reason"]
            )

        return result


jev_guardrail = JevClassifierGuardrail()
