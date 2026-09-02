"""
Central rules engine: loads heuristic rules from MongoDB, caches in Redis DB3,
and exposes an in-memory RulesBundle for ThreatHeuristics analysis.
"""
import logging
from typing import Optional, List, Set

from core_orchestrator.domain.entities.rule_engine.rules import (
    RulesBundle,
    rules_to_bundle,
    hash_version,
    HeuristicRule,
    build_default_rules_bundle,
    RuleVersion,
    RuleAuditLog, RulesStatistics, HealthStatus, RuleMatch, MITRE_CATALOG,
)
from core_orchestrator.application.modules.rules_heuristics.rule_service import RuleService
from core_orchestrator.domain.entities.telemetry import TelemetryWindow
from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import map_to_dataclass
from shared.rules_seed import load_rules_seed_payload

logger = logging.getLogger(__name__)

class RulesEngineService:
    def __init__(self, rules_service: RuleService):
        self._service = rules_service
        self._logger = logger
        self._initialized = False
        self._memory_bundle: Optional[RulesBundle] = None
        self._last_source: str = "fallback"

    async def initialize(self) -> bool:
        """
        Initializes the RulesEngine by loading the current active rules into memory.

        This method attempts to fetch the active set of rules and store it in memory for
        future processing. If initialization fails for any reason, it falls back to a
        default set of rules and marks the engine as initialized.

        Returns:
            bool: True if the initialization was successful, False otherwise.
        """
        try:
            # Initialize global bundle by default (client_id=None).
            bundle = await self.get_active_rules(client_id=None)
            self._memory_bundle = bundle
            self._initialized = True
            self._logger.info(
                "RulesEngine initialized (version=%s, ua_keywords=%d, uris=%d)",
                bundle.version_hash,
                len(bundle.malicious_ua_keywords),
                len(bundle.sensitive_uris),
            )
            return True
        except Exception as exc:
            self._logger.error("RulesEngine initialization failed: %s", exc)
            self._memory_bundle = self._get_default_rules()
            self._last_source = "fallback"
            self._initialized = True
            return False

    async def get_active_rules(self, client_id: Optional[str] = None) -> RulesBundle:
        """
        Retrieves the active rules for a given client. Rules can be fetched from cache,
        MongoDB, or a fallback mechanism, with data isolation based on the client ID.

        Parameters:
            client_id (Optional[str]): The ID of the client whose active rules are
                being retrieved. If no client ID is provided, global rules are used.

        Returns:
            RulesBundle: The bundle of active rules for the specified client or
                global rules if no client ID is provided.

        Raises:
            Exception: Logs a warning if rules cannot be loaded from MongoDB and
                 fall back to default rules.

        """
        # Try cache first (key includes client_id for isolation)
        cache_key_suffix = client_id or "global"
        cached = await self._service.get_cached_rules_for_tenant(cache_key_suffix)
        if cached and cached.malicious_ua_keywords:
            self._memory_bundle = cached
            self._last_source = "cache"
            return cached

        try:
            # Load client + global rules merged with client precedence.
            rules = await self._service.get_active_rules_by_client(client_id)
            if not rules:
                seeded_bundle = await self._seed_rules_store_if_empty()
                if seeded_bundle is not None:
                    self._memory_bundle = seeded_bundle
                    self._last_source = "mongodb"
                    return seeded_bundle
            if rules:
                active_version = await self._service.get_active_version(client_id)
                version_hash = active_version.version_hash if active_version else hash_version(rules)
                bundle = rules_to_bundle(rules, version_hash=version_hash)

                await self._service.cache_rules_for_tenant(bundle, cache_key_suffix=cache_key_suffix)
                self._memory_bundle = bundle
                self._last_source = "mongodb"
                return bundle
        except Exception as exc:
            self._logger.warning("Failed to load rules from MongoDB: %s", exc)

        fallback = self._get_default_rules()
        self._memory_bundle = fallback
        self._last_source = "fallback"
        return fallback


    async def get_rules_stats(self) -> RulesStatistics:
        """
        Retrieves statistics about active rules.

        This asynchronous method gathers statistics related to active rules in the
        system, including the total number of active rules, version information,
        cache status, and last updated timestamp.

        Returns:
            RulesStatistics: A dataclass instance containing the statistics for the
            active rules.

        """
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._service.get_cached_rules() is not None
        rules = await self._service.list_all_active_rules_internal()
        return RulesStatistics(
            total_active_rules=len(rules),
            version_hash=bundle.version_hash,
            cached=cached,
            last_updated=bundle.last_updated,
        )

    async def health_check(self) -> HealthStatus:
        """
        Checks the health status of the system.

        This method evaluates the system health by checking if the rules are
        loaded, determining their source, and verifying if cached rules exist.
        The method provides a detailed health status including the current state
        of initialization, the source of the rules, and metadata about the rules.

        Returns:
            HealthStatus: An object representing the system health, including the
            current status (healthy or initializing), whether the rules are cached,
            the version hash of the active rules, the last update timestamp, and
            the source of the rules.

        """
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._service.get_cached_rules() is not None
        return HealthStatus(
            status="healthy" if self._initialized else "initializing",
            cached=cached,
            version_hash=bundle.version_hash,
            last_updated=bundle.last_updated,
            source=self._last_source if not cached else "cache",
        )

    def evaluate_window(self, telemetry_window: TelemetryWindow) -> List[RuleMatch]:
        """
        Evaluates a telemetry window to detect sensitive URI accesses and applies
        rules from the loaded memory bundle or a default rules bundle.

        Parameters:
        telemetry_window (TelemetryWindow): The telemetry data window containing
        a list of URIs to be evaluated.

        Returns:
        List[str]: A list of rule identifiers that were matched during the evaluation.
        """
        bundle = self._memory_bundle or build_default_rules_bundle()
        matches: List[RuleMatch] = []

        matches.extend(self._eval_user_agents(telemetry_window.user_agents_observed, bundle))
        matches.extend(self._eval_sensitive_uris(telemetry_window.unique_uris_requested, bundle))

        payload_targets = self._extract_payload_targets(telemetry_window)
        matches.extend(self._eval_injections(payload_targets, bundle))

        return matches

    @staticmethod
    def _eval_user_agents(uas: List[str], bundle: RulesBundle) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        mitre_info = MITRE_CATALOG.get("user_agent")
        for ua in filter(None, uas):
            ua_lower = ua.lower()
            for keyword, score in bundle.malicious_ua_keywords.items():
                if keyword.lower() in ua_lower:
                    matches.append(RuleMatch(
                        category="user_agent",
                        match_value=keyword,
                        score=score,
                        evidence=f"User-Agent '{ua}' matches the keyword '{keyword}'",
                        mitre=mitre_info
                    ))
        return matches

    @staticmethod
    def _eval_sensitive_uris(uris: List[str], bundle: RulesBundle) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        mitre_info = MITRE_CATALOG.get("uri")
        for uri in filter(None, uris):
            uri_lower = uri.lower()
            for sensitive_path, score in bundle.sensitive_uris.items():
                if sensitive_path.lower() in uri_lower:
                    matches.append(RuleMatch(
                        category="uri",
                        match_value=sensitive_path,
                        score=score,
                        evidence=f"Access to sensitive resource '{sensitive_path}' at URI '{uri}'",
                        mitre=mitre_info
                    ))
        return matches

    @staticmethod
    def _eval_injections(targets: Set[str], bundle: RulesBundle) -> List[RuleMatch]:
        """
        Evaluates potential injection vulnerabilities in the provided target strings based on defined patterns
        and returns a list of detected matches.

        This method iterates through a set of target strings and checks for patterns indicating SQL injection
        or path traversal vulnerabilities using the provided rules bundle. If a match is found, it creates a
        RuleMatch object with details about the vulnerability and appends it to the result list.

        Parameters:
        targets: Set[str]
            A set of target strings to evaluate for injection vulnerabilities.
        bundle: RulesBundle
            An object containing patterns and scores to detect and evaluate SQL Injection and
            Path Traversal vulnerabilities.

        Returns:
        List[RuleMatch]
            A list of RuleMatch objects representing the identified vulnerabilities in the target strings.
        """
        matches: List[RuleMatch] = []
        sqli_mitre = MITRE_CATALOG.get("sql_injection")
        path_traversal_mitre = MITRE_CATALOG.get("path_traversal")
        for target in targets:
            target_lower = target.lower()

            # SQL Injection
            for pattern in bundle.sql_injection_patterns:
                if pattern.lower() in target_lower:
                    matches.append(RuleMatch(
                        category="injection",
                        match_value=pattern,
                        score=bundle.sql_injection_score,
                        evidence=f"SQL injection pattern {pattern} detected in: {target[:100]}",
                        mitre=sqli_mitre,
                    ))

            # Path Traversal
            for pattern in bundle.path_traversal_patterns:
                if pattern.lower() in target_lower:
                    matches.append(RuleMatch(
                        category="injection",
                        match_value=pattern,
                        score=bundle.path_traversal_score,
                        evidence=f"Path Traversal pattern {pattern} detected in: {target[:100]}",
                        mitre=path_traversal_mitre,
                    ))
        return matches

    @staticmethod
    def _extract_payload_targets(telemetry_window: TelemetryWindow) -> Set[str]:
        """
        Extracts unique target identifiers from a telemetry window.

        This method combines unique URIs, critical payload features, and attributes from
        suspicious samples within the provided telemetry window to produce a set of
        unique target identifiers. The target identifiers are filtered to exclude any
        empty entries.

        Parameters:
            telemetry_window (TelemetryWindow): The telemetry window containing data
            from which target identifiers are extracted.

        Returns:
            Set[str]: A set of unique target identifiers extracted from the telemetry
            window.
        """
        targets = set(telemetry_window.unique_uris_requested) | set(telemetry_window.critical_payload_features)
        return {t for t in targets if t}

    @staticmethod
    def _get_default_rules() -> RulesBundle:
        return build_default_rules_bundle()

    async def _seed_rules_store_if_empty(self) -> Optional[RulesBundle]:
        """Bootstrap the dedicated rules DB (`heuristy`) from the canonical seed file."""
        payload = load_rules_seed_payload()
        rules = [map_to_dataclass(HeuristicRule, doc) for doc in payload.get("heuristic_rules", [])]
        if not rules:
            return None

        versions = [map_to_dataclass(RuleVersion, doc) for doc in payload.get("rule_versions", [])]
        audits = [map_to_dataclass(RuleAuditLog, doc) for doc in payload.get("rule_audit_log", [])]

        for rule in rules:
            await self._service.create_rule(rule)

        for version in versions:
            await self._service.create_version(version)

        for audit in audits:
            await self._service.log_rule_action(
                action=audit.action,
                rule_id=audit.rule_id,
                user=audit.user,
                changes=audit.changes,
                reason=audit.reason,
                ip_address=audit.ip_address,
                client_id=audit.client_id,
            )

        active_version = next((version for version in versions if version.is_active), None)
        version_hash = active_version.version_hash if active_version else hash_version(rules)
        bundle = rules_to_bundle(rules, version_hash=version_hash)
        await self._service.cache_rules(bundle)
        self._last_source = "mongodb"

        self._logger.info(
            "Seeded rules store with active rules from seed payload"
        )
        return bundle
