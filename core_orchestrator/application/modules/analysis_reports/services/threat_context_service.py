"""
Service responsible for enriching analysis results with historical threat context.
"""
import logging
from typing import Dict, Any

from core_orchestrator.domain.ports.telemetry.threat_context_port import ThreatContextPort
from core_orchestrator.domain.ports.telemetry.threat_context_service_port import ThreatContextServicePort

logger = logging.getLogger(__name__)


class ThreatContextService(ThreatContextServicePort):
    def __init__(self, threat_context_port: ThreatContextPort):
        self.threat_context_port = threat_context_port

    async def get_historical_context(self, source_ip: str) -> Dict[str, Any]:
        """
        Retrieves historical threat context for a given source IP.
        """
        logger.info(f"Requesting historical context for {source_ip}")
        context_result = await self.threat_context_port.get_threat_context(source_ip=source_ip, limit=5)

        history = context_result.get("history", [])
        logger.info(f"Historical context added: {len(history)} previous alerts for {source_ip}")
        return {"threat_history": history}


