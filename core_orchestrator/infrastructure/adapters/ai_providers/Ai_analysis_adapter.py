"""Service responsible for analyzing telemetry data."""
import json
import logging
from typing import Any, Dict, List
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.application.modules.rules_heuristics.rules_engine_service import RulesEngineService
from core_orchestrator.domain.entities.rule_engine.rules import RuleMatch, TACTIC_TO_KILL_CHAIN

from core_orchestrator.domain.entities.telemetry import TelemetryWindow
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.domain.object_value.telemetry import ThreatLevel

from core_orchestrator.domain.ports import AiAnalysisPort, LlmAnalysisPort
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.infrastructure.adapters.ai_providers.prompt_factory import build_web_activity_prompt
from core_orchestrator.infrastructure.adapters.ai_providers.provider_factory import ProviderFactory


logger = logging.getLogger(__name__)


class AiAnalysisAdapter(AiAnalysisPort):

    def __init__(
        self,
        llm_analysis: LlmAnalysisPort,
        provider_factory: ProviderFactory,
        rules_engine_service: RulesEngineService,
        tenant_provider_service: TenantProviderAiService,
    ):

        self.llm_analysis = llm_analysis
        self.provider_factory = provider_factory
        self.rules_engine_service = rules_engine_service
        self.tenant_provider_service = tenant_provider_service

    async def get_provider_for_tenant(self, tenant_id: str) -> AiProvider:
        tenant_config = await self.tenant_provider_service.get_tenant_by_client_id(tenant_id)
        if not tenant_config:
            raise ValueError(f"Tenant configuration not found.: {tenant_id}")

        model_default_telemetry = tenant_config.default_log_analysis_model_id
        if not model_default_telemetry:
            raise ValueError(f"The tenant {tenant_id} does not have a default model configured.")

        model_definition = tenant_config.available_models.get(model_default_telemetry)
        if not model_definition:
            raise ValueError(f"The model {model_default_telemetry} is not present in 'available_models'.")

        if not model_definition.enabled:
            raise ValueError(f"The model {model_default_telemetry} is disabled for the tenant {tenant_id}.")

        provider_config = next(
            (
                provider for provider in tenant_config.ai_providers
                if provider.provider.lower() == model_definition.provider.lower()
            ),
            None
        )
        if not provider_config:
            raise ValueError(
                f"No credentials/configuration found for provider '{model_definition.provider}'"
                f"associated with the model '{model_definition}'."
            )


        return self.provider_factory.create_provider(
            provider_config=provider_config,
            model_definition=model_definition
        )

    async def analyze_activity(self, telemetry_window: TelemetryWindow) -> AnalysisReport|None:
        """analyze web activity and returns a sanitized result."""
        source_ip = telemetry_window.source_ip
        client_id = telemetry_window.client_id or ""

        # step 1
        deterministic_matches = self.rules_engine_service.evaluate_window(telemetry_window)
        if not deterministic_matches:
            logger.info(
                "No heuristic threats detected for source_ip=%s window_id=%s. Skipping LLM call.",
                source_ip,
                telemetry_window.window_id,
            )
            return None
        rule_evidences = [match.evidence for match in deterministic_matches]
        deterministic_score = sum(match.score for match in deterministic_matches)
        logger.info(
            "Deterministic matches count=%d total_score=%d for source_ip=%s window_id=%s",
            len(deterministic_matches),
            deterministic_score,
            source_ip,
            telemetry_window.window_id,
        )
        # Supplier selection by tenant
        provider = await self.get_provider_for_tenant(tenant_id=client_id)
        logger.info(
            "Selected AI provider=%s for source_ip=%s window_id=%s",
            provider.provider_name,
            source_ip,
            telemetry_window.window_id,
        )
        prompt = build_web_activity_prompt(
            telemetry=telemetry_window,
            provider_name=provider.provider_name,
            rule_score=deterministic_score,
            rule_evidences=rule_evidences
        )

        analysis_result = await self.llm_analysis.ask_llm(ia_provider_client=provider, prompt=prompt)
        report = self._build_safe_analysis_result(analysis_result, telemetry_window, source_ip,deterministic_matches)

        if report is None:
            logger.info(
                "LLM returned an unsupported payload for source_ip=%s window_id=%s; telemetry report will not be persisted.",
                source_ip,
                telemetry_window.window_id,
            )
            raise ValueError("LLM returned an unsupported payload")

        logger.info(
            "Analysis completed for source_ip=%s window_id=%s threat_detected=%s threat_level=%s threat_score=%s",
            source_ip,
            telemetry_window.window_id,
            report.threat_detected,
            report.threat_level,
            report.threat_score,
        )
        return report

    @staticmethod
    def _build_safe_analysis_result(analysis_result: Dict[str, Any] | str,
                                    telemetry_window: TelemetryWindow,
                                    source_ip: str,
                                    rule_matches: List[RuleMatch],
                                    ) -> AnalysisReport:
        """
        Builds a safe and normalized analysis report based on input data, applying validation,
        fallbacks, and calculated metrics.

        Summary:
        This method transforms potentially inconsistent or incomplete input data from an analysis
        process or LLM response into a standardized and complete `AnalysisReport` object. It ensures
        data integrity by validating and normalizing input fields, estimating threat scores when needed,
        and assigning threat levels and associated metadata.

        The method integrates scoring mechanisms, maps detected threats to a structured output (MITRE ATT&CK
        mappings if applicable), and summarizes findings and recommendations. It also incorporates contextual
        information such as telemetry data and source details to enhance the final analysis.

        Args:
            analysis_result (Dict[str, Any] | str): Raw analysis output, either as a dictionary of
                structured fields or a plain string response summarizing the analysis
            telemetry_window (TelemetryWindow): Container for telemetry data collected during the
                analysis window, supplying source identifiers, request logs, and other metadata
            source_ip (str): The source IP address tied to the analysis
            rule_matches (List[RuleMatch]): List of individual rule matches contributing to the overall
                assessment. Each match contains details like scoring, category, and evidence.

        Returns:
            AnalysisReport: A validated and normalized analysis report instance containing detailed
                threat assessment, associated indicators, and recommendations.
        """
        # 1. Normalize LLM input response
        payload = analysis_result.copy()
        if "content" in payload and isinstance(payload["content"], str):
            try:
                parsed_content = json.loads(payload["content"])
                if isinstance(parsed_content, dict):
                    payload = parsed_content
            except (json.JSONDecodeError, TypeError):
                payload = {"reasoning_summary": payload["content"]}

        safe = {
            "threat_score": payload.get("threat_score", 0),
            "reasoning_summary": payload.get("reasoning_summary") or payload.get(
                "analysis") or "No explicit analysis available.",
            "recommendation": payload.get("recommendation", "Continue standard telemetry monitoring.")
        }

        # 2. Calculate Score (Prioritize LLM, fallback to a sum of rule_matches)
        raw_score = safe.get("threat_score",0)
        try:
            llm_score = int(raw_score) if raw_score is not None else None
        except (ValueError, TypeError):
            llm_score = None

        rule_score = sum(m.score for m in rule_matches)

        final_score = llm_score if llm_score is not None else rule_score
        final_score = max(0, min(100, final_score))

        safe["threat_score"] = final_score

        # 3. Assign ThreatLevel directly using the provided Enum class.
        calculated_level = ThreatLevel.from_score(final_score) or ThreatLevel.NONE
        safe["threat_level"] = calculated_level.value
        safe["threat_detected"] = calculated_level in (
            ThreatLevel.CRITICAL,
            ThreatLevel.HIGH,
            ThreatLevel.MEDIUM,
        )

        # 4. Build indicators directly from RuleMatches.
        indicators = [f"[{m.category.upper()}] {m.evidence}" for m in rule_matches]

        # Fallback if no rules were present but a threat was detected
        if not indicators and safe["threat_detected"]:
            uris = getattr(telemetry_window, "unique_uris_requested", [])
            uri_context = f" en URIs: {', '.join(uris[:3])}" if uris else ""
            indicators = [f"[TELEMETRY] Suspicious behavior detected for the IP {source_ip}{uri_context}"]

        safe["indicators_found"] = indicators

        # 5. Get MITRE mapping from the rule with the highest impact (RuleMatch)
        primary_mitre = RuleMatch.extract_primary_mitre(rule_matches)
        if primary_mitre:
            safe["mitre_tactic"] = primary_mitre.tactic
            safe["mitre_tactic_id"] = primary_mitre.tactic_id
            safe["mitre_technique"] = primary_mitre.technique
            safe["mitre_technique_id"] = primary_mitre.technique_id
            safe["mitre_sub_technique"] = primary_mitre.sub_technique
            safe["mitre_sub_technique_id"] = primary_mitre.sub_technique_id
            safe["kill_chain_phase"] = TACTIC_TO_KILL_CHAIN.get(primary_mitre.tactic, "Delivery")
        elif safe["threat_detected"]:
            safe["mitre_tactic"] = "Initial Access"
            safe["mitre_tactic_id"] = "TA0001"
            safe["mitre_technique"] = "Exploit Public-Facing Application"
            safe["mitre_technique_id"] = "T1190"
            safe["mitre_sub_technique"] = None
            safe["mitre_sub_technique_id"] = None
            safe["kill_chain_phase"] = TACTIC_TO_KILL_CHAIN.get(safe["mitre_tactic"] , "Delivery")


        # 6. Map LLM schemas with secure fallbacks
        safe["reasoning_summary"] = safe.get("reasoning_summary") or "No explicit analysis available."
        safe["recommendation"] = safe.get("recommendation") or "Continue with standard telemetry monitoring."

        # 7. assign mandatory window metadata
        safe["source_ip"] = source_ip
        safe["source_id"] = getattr(telemetry_window, "source_id", "unknown")
        safe["window_id"] = getattr(telemetry_window, "window_id", "unknown")
        safe["client_id"] = getattr(telemetry_window, "client_id", "unknown")

        uris = getattr(telemetry_window, "unique_uris_requested", [])
        safe["targeted_asset"] = ", ".join(uris[:5]) if uris else f"IP: {source_ip}"

        # 8. Return the validated instance
        return AnalysisReport(**safe)


