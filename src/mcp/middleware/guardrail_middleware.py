"""
AI-Driven Intent Guardrail using TypeSafe AI JEV Model.
Classifier-as-a-Judge real-time semantic evaluation of tool payloads before DB execution.
"""

import time
from typing import Any

import httpx
import structlog

from src.core.config import settings
from src.core.exceptions import GuardrailViolationError

logger = structlog.get_logger(__name__)


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
                "classification": str,     # 'SAFE', 'MALICIOUS_INJECTION', 'EXFILTRATION', etc.
                "reason": str,
                "latency_ms": float
            }
        """
        if not settings.JEV_ENABLED:
            return {
                "risk_score": 0.0,
                "classification": "SAFE",
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
        classification, risk_score, reason = self._embedded_classify(tool_name, arguments)

        return {
            "risk_score": risk_score,
            "classification": classification,
            "reason": reason,
            "latency_ms": latency
        }

    def _embedded_classify(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, float, str]:
        """Embedded fast heuristic classifier simulating JEV inference rules."""
        raw_text = str(arguments).lower()

        # Critical attack signatures
        jailbreak_indicators = [
            "pg_sleep",
            "copy",
            "program",
            "pg_read_file",
            "information_schema.tables",
            "union select",
            "current_setting",
            "admin_credentials",
            "drop table",
            "or 1=1",
            "curl "
        ]

        for pattern in jailbreak_indicators:
            if pattern in raw_text:
                return (
                    "MALICIOUS_INJECTION",
                    0.98,
                    f"Payload matches high-risk pattern '{pattern}' indicating privilege escalation or data exfiltration"
                )

        return ("SAFE", 0.02, "Query intent classified as benign parameterized operation")

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
                reason=result["reason"]
            )
            raise GuardrailViolationError(
                f"Blocked by TypeSafe AI JEV Guardrail: {result['classification']} (Score: {result['risk_score']:.2f})",
                risk_score=result["risk_score"],
                classification=result["classification"],
                reason=result["reason"]
            )

        return result


jev_guardrail = JevClassifierGuardrail()
