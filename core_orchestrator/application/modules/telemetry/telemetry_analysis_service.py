"""Core orchestrator agent module.

Manages the AI reasoning loop, translating security requirements into
MCP tool calls and consolidating the final verdict.
"""

import logging
import json


from core_orchestrator.domain.entities.telemetry import TelemetryWindow
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.domain.ports.telemetry.telemetry_ia_analysis_port import AiAnalysisPort
from core_orchestrator.domain.ports.telemetry.telemetry_reports_port import AnalyticsReportsPort


logger = logging.getLogger("core_orchestrator.agent.orchestrator")


class TelemetryAnalysisService:
    """
    Controller responsible for orchestration and tool
    invocation under the MCP protocol.
    """

    def __init__(
        self,
        ia_analysis: AiAnalysisPort,
        analytics_report: AnalyticsReportsPort,
    ):
        """
        Initializes the agent and the associated MCP client.
        """
        self.ia_analysis = ia_analysis
        self.analytics_service = analytics_report

    async def _save_report(self, analysis_result:AnalysisReport):
        """Saves the final analysis report to the database."""

        logger.info(
            "Saving analysis report for source_ip=%s window_id=%s threat_level=%s threat_detected=%s",
            analysis_result.source_ip,
            analysis_result.window_id,
            analysis_result.threat_level,
            analysis_result.threat_detected,
        )
        await self.analytics_service.create_report(analysis_result)
        logger.info(
            "Analysis report persisted for source_ip=%s window_id=%s",
            analysis_result.source_ip,
            analysis_result.window_id,
        )

    async def process_telemetry_window(self, telemetry_window: TelemetryWindow) -> str:
        """
        Initiates the analytical reasoning cycle for a telemetry time window.
        """
        source_ip = telemetry_window.source_ip

        try:
            logger.info(
                "Running telemetry analysis for source_ip=%s window_id=%s",
                source_ip,
                telemetry_window.window_id,
            )
            analysis_result = await self.ia_analysis.analyze_activity(telemetry_window)
            logger.info(
                "Analysis completed for source_ip=%s window_id=%s threat_detected=%s threat_level=%s",
                source_ip,
                telemetry_window.window_id,
                analysis_result.threat_detected,
                analysis_result.threat_level,
            )

            await self._save_report(analysis_result)

            logger.info(
                "Telemetry analysis workflow finished for source_ip=%s window_id=%s",
                source_ip,
                telemetry_window.window_id,
            )
            final_report_json = json.dumps(analysis_result, indent=2, ensure_ascii=False, default=str)
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
