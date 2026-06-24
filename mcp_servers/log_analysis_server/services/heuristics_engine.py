"""
Deterministic heuristics engine module for threat analysis.

Implements rule-based analysis to detect attack patterns without relying
on the LLM, providing a confidence baseline for threat scoring.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle
from shared.rules_seed import build_seed_bundle_payload

logger = logging.getLogger(__name__)


class ThreatHeuristics:
    """Heuristic analysis engine for risk score calculation (0-100%)."""

    @staticmethod
    def analyze(
        telemetry: WebActivityWindowInput,
        rules_bundle: Optional[RulesBundle] = None,
    ) -> Tuple[int, List[str], str]:
        """
        Executes full heuristic analysis on a telemetry window.

        Args:
            telemetry (WebActivityWindowInput): Data of the window to analyze
            rules_bundle (RulesBundle, optional): Dynamic rules from MongoDB/Redis.
                Falls back to class-level defaults when not provided.

        Returns:
            Tuple[int, List[str], str]: (threat_score, indicators, reasoning)
        """
        rules = rules_bundle or ThreatHeuristics._get_default_rules()
        threat_score = 0
        indicators = []
        reasoning_parts = []

        source_ip = telemetry.source_ip
        total_requests = telemetry.total_requests

        ua_score, ua_indicators = ThreatHeuristics._analyze_user_agents(
            telemetry.user_agents_observed, rules.malicious_ua_keywords
        )
        if ua_score > 0:
            threat_score += ua_score
            indicators.extend(ua_indicators)
            reasoning_parts.append(f"Malicious User-Agent (+{ua_score})")
        
        # ============================================================
        # 2. SENSITIVE URI ANALYSIS
        # ============================================================
        uri_score, uri_indicators = ThreatHeuristics._analyze_sensitive_uris(
            telemetry.unique_uris_requested, rules.sensitive_uris
        )
        if uri_score > 0:
            threat_score += uri_score
            indicators.extend(uri_indicators)
            reasoning_parts.append(f"Sensitive URIs detected (+{uri_score})")
        
        # ============================================================
        # 3. RESPONSE CODE ANALYSIS (404 Ratio)
        # ============================================================
        error_score, error_indicators = ThreatHeuristics._analyze_response_codes(
            telemetry.response_codes_distribution,
            total_requests
        )
        if error_score > 0:
            threat_score += error_score
            indicators.extend(error_indicators)
            reasoning_parts.append(f"Response code anomaly (+{error_score})")
        
        # ============================================================
        # 4. SPEED ANALYSIS (Anomalous RPS)
        # ============================================================
        rps_score, rps_indicators = ThreatHeuristics._analyze_requests_per_second(
            telemetry.requests_per_second_avg,
            total_requests
        )
        if rps_score > 0:
            threat_score += rps_score
            indicators.extend(rps_indicators)
            reasoning_parts.append(f"Anomalous RPS (+{rps_score})")
        
        # ============================================================
        # 5. HTTP METHOD DIVERSITY ANALYSIS
        # ============================================================
        method_score, method_indicators = ThreatHeuristics._analyze_http_methods(
            telemetry.http_methods_distribution
        )
        if method_score > 0:
            threat_score += method_score
            indicators.extend(method_indicators)
            reasoning_parts.append(f"Anomalous HTTP distribution (+{method_score})")
        
        # ============================================================
        # 6. SQL INJECTION / PATH TRAVERSAL ANALYSIS
        # ============================================================
        injection_score, injection_indicators = ThreatHeuristics._analyze_injection_patterns(
            telemetry.unique_uris_requested,
            rules.sql_injection_patterns,
            rules.path_traversal_patterns,
            rules.sql_injection_score,
            rules.path_traversal_score,
        )
        if injection_score > 0:
            threat_score += injection_score
            indicators.extend(injection_indicators)
            reasoning_parts.append(f"Injection patterns detected (+{injection_score})")
        
        # ============================================================
        # 7. NORMALIZATION AND LIMITS (0-100)
        # ============================================================
        # Normalize: scaled sum and asymmetry
        threat_score = min(100, int(threat_score))
        
        # Generate synthetic reasoning
        reasoning = f"Heuristic analysis of {source_ip}: "
        if reasoning_parts:
            reasoning += "; ".join(reasoning_parts) + "."
        else:
            reasoning += "No threat indicators detected."
        
        return threat_score, indicators, reasoning

    @staticmethod
    def _get_default_rules() -> RulesBundle:
        """Build fallback RulesBundle from the persisted rules seed file."""
        return RulesBundle.from_cache_dict(build_seed_bundle_payload())

    @staticmethod
    def _analyze_user_agents(
        user_agents: List[str],
        keywords: Dict[str, int],
    ) -> Tuple[int, List[str]]:
        """Detects malicious User-Agents or scanning tools."""
        score = 0
        indicators = []

        for ua in user_agents:
            ua_lower = ua.lower()
            for keyword, ua_score in keywords.items():
                if keyword in ua_lower:
                    score += ua_score
                    tool_name = keyword.upper()
                    if "nikto" in keyword:
                        indicators.append(f"🔴 Scanning tool detected: {tool_name} (Nikto Web Scanner - Vulnerability enumeration)")
                    elif "sqlmap" in keyword:
                        indicators.append(f"🔴 Specialized tool detected: {tool_name} (SQL Injection Tester - Direct DB attack)")
                    elif "metasploit" in keyword:
                        indicators.append(f"🔴 Exploitation framework detected: {tool_name} (Metasploit - Offensive tool)")
                    elif "nmap" in keyword:
                        indicators.append(f"🔴 Reconnaissance tool detected: {tool_name} (Network Mapper - Port/service mapping)")
                    else:
                        indicators.append(f"🟠 Suspicious User-Agent: {ua} (Testing/scanning tool: {tool_name})")
                    break
        
        return score, indicators

    @staticmethod
    def _analyze_sensitive_uris(
        uris: List[str],
        sensitive_uris: Dict[str, int],
    ) -> Tuple[int, List[str]]:
        """Detects requests to sensitive paths."""
        score = 0
        indicators = []

        for uri in uris:
            uri_lower = uri.lower()
            for sensitive_path, path_score in sensitive_uris.items():
                if sensitive_path in uri_lower:
                    score += path_score
                    indicators.append(f"Request to sensitive path: {uri}")
                    break
        
        return score, indicators

    @staticmethod
    def _analyze_response_codes(response_dist: Dict[str, int], total: int) -> Tuple[int, List[str]]:
        """Analyzes the response code distribution to detect enumeration."""
        score = 0
        indicators = []
        
        # Count 404s
        code_404_count = response_dist.get("404", 0)
        if total > 0:
            error_ratio = code_404_count / total
            
            # If more than 60% are 404, it is likely enumeration
            if error_ratio > 0.6:
                score += 30
                indicators.append(f"High 404 error ratio: {error_ratio:.1%} ({code_404_count}/{total})")
            elif error_ratio > 0.4:
                score += 15
                indicators.append(f"Moderate 404 error ratio: {error_ratio:.1%}")
        
        # Count other error codes (5xx)
        code_5xx_count = sum(v for k, v in response_dist.items() if k.startswith("5"))
        if code_5xx_count > 3:
            score += 10
            indicators.append(f"Multiple server errors (5xx): {code_5xx_count}")
        
        # Count denied access (403)
        code_403_count = response_dist.get("403", 0)
        if code_403_count > 5:
            score += 10
            indicators.append(f"Multiple access denied (403): {code_403_count}")
        
        return score, indicators

    @staticmethod
    def _analyze_requests_per_second(rps: float, total_requests: int) -> Tuple[int, List[str]]:
        """Detects anomalous request rates (fast or slow scanning)."""
        score = 0
        indicators = []
        
        # High RPS (more than 10 req/s is suspicious for a normal user)
        if rps > 10.0:
            score += 25
            indicators.append(f"High RPS detected: {rps:.2f} requests/second")
        elif rps > 5.0:
            score += 10
            indicators.append(f"Moderately high RPS: {rps:.2f} requests/second")
        
        # Many requests in a short window
        if total_requests > 50 and rps < 5.0:
            score += 15
            indicators.append(f"Burst of {total_requests} requests in short time window")
        
        return score, indicators

    @staticmethod
    def _analyze_http_methods(methods_dist: Dict[str, int]) -> Tuple[int, List[str]]:
        """Detects unusual HTTP method usage."""
        score = 0
        indicators = []
        
        suspicious_methods = ["DELETE", "TRACE", "CONNECT", "OPTIONS"]
        for method in suspicious_methods:
            if methods_dist.get(method, 0) > 0:
                score += 10
                indicators.append(f"Suspicious HTTP method: {method} ({methods_dist[method]} requests)")
        
        # POST without GET is unusual
        post_count = methods_dist.get("POST", 0)
        get_count = methods_dist.get("GET", 0)
        if post_count > 5 and get_count == 0:
            score += 15
            indicators.append(f"Unusual distribution: {post_count} POSTs without GETs")
        
        return score, indicators

    @staticmethod
    def _analyze_injection_patterns(
        uris: List[str],
        sql_patterns: List[str],
        traversal_patterns: List[str],
        sql_score: int = 30,
        traversal_score: int = 40,
    ) -> Tuple[int, List[str]]:
        """Detects SQL injection and path traversal patterns in URIs."""
        score = 0
        indicators = []

        for uri in uris:
            uri_lower = uri.lower()
            uri_decoded = uri_lower.replace("%27", "'").replace("%20", " ").replace("%2f", "/").replace("%5c", "\\")

            for pattern in traversal_patterns:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += traversal_score
                    indicators.append(f"🔴 Path traversal pattern detected: {uri}")
                    break

            for pattern in sql_patterns:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += sql_score
                    indicators.append(f"🔴 SQL injection pattern detected: {uri}")
                    break

        return score, indicators

