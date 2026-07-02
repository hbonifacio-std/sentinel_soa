"""Core orchestrator agent module.

Manages the AI reasoning loop, translating security requirements into
MCP tool calls and consolidating the final verdict.
"""

import logging
import json
from typing import Dict, Any

from core_orchestrator.domain.models.analysis import AnalysisReportResponse
from core_orchestrator.domain.ports.analysis.analysis_service_port import AnalysisServicePort
from core_orchestrator.domain.ports.telemetry.threat_context_service_port import ThreatContextServicePort
from core_orchestrator.domain.ports.telemetry.report_telemetry_service_port import ReportTelemetryServicePort
from core_orchestrator.domain.ports.shared.cache_port import CachePort

logger = logging.getLogger("core_orchestrator.agent.orchestrator")


class OrchestratorAgent:
    """
    Controller responsible for orchestration and tool
    invocation under the MCP protocol.
    """

    def __init__(
        self,
        cache_port: CachePort,
        analysis_service: AnalysisServicePort,
        analytics_service: ReportTelemetryServicePort,
        threat_context_service: ThreatContextServicePort,
    ):
        """
        Initializes the agent and the associated MCP client.
        """
        self.cache_port = cache_port
        self.analysis_service = analysis_service
        self.analytics_service = analytics_service
        self.threat_context_service = threat_context_service

    async def _check_cache(self, telemetry_payload: Dict[str, Any]) -> str | None:
        """Checks Redis for a cached analysis result."""
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        cache_key = f"cache:analysis:{json.dumps(telemetry_payload, sort_keys=True, default=str)}"
        cached_result = await self.cache_port.get(cache_key)
        if cached_result:
            logger.info(f"Analysis result found in cache for {source_ip}.")
            return cached_result
        return None

    async def _set_cache(self, telemetry_payload: Dict[str, Any], final_report_json: str):
        """Sets the analysis result in the Redis cache."""
        cache_key = f"cache:analysis:{json.dumps(telemetry_payload, sort_keys=True, default=str)}"
        await self.cache_port.set(cache_key, final_report_json, expire_seconds=3600)  # Cache for 1 hour

    async def _enrich_with_historical_context(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches the analysis result with historical threat context if a threat was detected."""
        source_ip = analysis_result.get("source_ip", "UNKNOWN")
        if not analysis_result.get("threat_detected", False):
            return analysis_result

        logger.info(f"Step 2: Threat detected. Requesting historical context for {source_ip}")

        context_result = await self.threat_context_service.get_historical_context(source_ip)
        analysis_result.update(context_result)

        logger.info(f"Historical context added: {len(analysis_result.get('threat_history', []))} previous alerts")
        return analysis_result

    async def _save_report(self, analysis_result: Dict[str, Any]):
        """Saves the final analysis report to the database."""
        source_ip = analysis_result.get("source_ip", "UNKNOWN")
        analysis_result.setdefault("reviewed", False)
        analysis_result.setdefault("actions", [])
        analysis_result.setdefault("resolved", False)

        report_data = AnalysisReportResponse.model_validate(analysis_result)
        await self.analytics_service.create_analysis_report(report_data=report_data)
        logger.debug(f"Analysis for {source_ip} saved to the database.")

    async def process_telemetry_window(self, telemetry_payload: Dict[str, Any]) -> str:
        """
        Initiates the analytical reasoning cycle for a telemetry time window.
        """
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info(f"Orchestrator Agent activated to analyze IP: {source_ip}")

        try:
            # Step 0: Check cache
            cached_result = await self._check_cache(telemetry_payload)
            if cached_result:
                return cached_result

            # Step 1: Analyze activity
            analysis_result = await self.analysis_service.analyze_activity(telemetry_payload)

            # Step 2: Enrich with historical context if needed
            analysis_result = await self._enrich_with_historical_context(analysis_result)

            # Step 3: Save the final report
            await self._save_report(analysis_result)

            final_report_json = json.dumps(analysis_result, indent=2, ensure_ascii=False, default=str)

            # Step 4: Cache the final result
            await self._set_cache(telemetry_payload, final_report_json)

            logger.info(f"Successfully processed and stored analysis for {source_ip}.")
            return final_report_json

        except Exception as exc:
            logger.exception("Failure during the Orchestrator Agent's reasoning cycle: %s", exc)
            return json.dumps({
                "status": "error",
                "error": str(exc),
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_level": "NONE"
            }, ensure_ascii=False)

