"""
Deterministic heuristics engine module for threat analysis.

Implements rule-based analysis to detect attack patterns without relying
on the LLM, providing a confidence baseline for threat scoring.
"""

import logging
from typing import Dict, List, Tuple, Any
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput

logger = logging.getLogger(__name__)


class ThreatHeuristics:
    """Heuristic analysis engine for risk score calculation (0-100%)."""
    
    # Threat indicator dictionaries
    MALICIOUS_UA_KEYWORDS = {
        # Vulnerability scanning tools
        "nikto": 30,        # Nikto is a very specific scanner
        "nmap": 25,
        "sqlmap": 35,       # SQLmap is extremely dangerous
        "dirbuster": 25,
        "masscan": 20,
        "nessus": 20,
        "openvas": 20,
        "metasploit": 30,
        "burp": 15,         # Testing but can be malicious
        "owasp": 8,
        "appscan": 12,
        "acunetix": 15,
        "wpscan": 20,
        "paramspider": 20,
        "nuclei": 25,
        "zaproxy": 10,
        "commix": 30,
        "xssstrike": 30,
        "wafw00f": 20,
        "gothumb": 20,
        "whatweb": 20,
        "joomscan": 25,
        "cmsmap": 25,
        "scanner": 20,      # Generic
        "bot": 8,           # Generic, low risk
        "crawler": 3,       # Legitimate
        "spider": 3,        # Legitimate
        "httpx": 25,        # Probing tool
        "subfinder": 20,    # Subdomain enumeration
    }
    
    SENSITIVE_URIS = {
        # Operating system files
        "/etc/passwd": 45,
        "/etc/shadow": 50,
        "/etc/sudoers": 50,
        "/etc/hosts": 30,
        "/etc/resolv.conf": 30,
        # Administrative panels and control panels
        "/admin": 20,
        "/wp-admin": 25,
        "/wp-login": 18,
        "/admin/login.php": 25,
        "/administrator": 25,
        "/cpanel": 30,
        "/phpmyadmin": 35,
        # Configuration files
        "/.env": 40,
        "/.git": 35,
        "/.git/config": 45,
        "/config": 25,
        "/.env.local": 40,
        "/.env.dev": 40,
        "/.env.prod": 40,
        "/web.config": 30,
        "/.aws": 35,
        "/.ssh": 40,
        "/config.php": 30,
        "/settings.json": 25,
        # Backup and database files
        "/backup": 20,
        "/backups": 20,
        "/.sql": 30,
        "/.db": 30,
        "/database.sql": 35,
        "/dump": 25,
        # ASP.NET / PHP
        "/admin.php": 25,
        "/login.php": 12,
        "/shell.php": 50,
        "/webshell": 50,
        "/cmd.php": 50,
        "/php.ini": 40,
        "/.htaccess": 25,
        # Project files
        "/composer.json": 15,
        "/package.json": 12,
        "/pom.xml": 12,
        "/requirements.txt": 15,
        # Dangerous directories
        "/var/www": 20,
        "/uploads": 15,
        "/tmp": 15,
    }
    
    SQL_INJECTION_PATTERNS = [
        # Basic patterns
        "' OR '1'='1",
        "' OR 1=1",
        "' OR 'a'='a",
        "admin'--",
        "admin'#",
        # UNION-based
        "' UNION SELECT",
        "UNION SELECT",
        # URL-encoded variants to catch %27
        "%27 OR %271%27=%271",
        "%27 OR 1=1",
        "%27 UNION SELECT",
        # Advanced techniques
        "EXEC",
        "EXECUTE",
        "DROP TABLE",
        "INSERT INTO",
        "DELETE FROM",
        "SHUTDOWN",
        "WAITFOR",
        "xp_",  # SQL Server malicious stored procedures
        # Boolean-based blind
        "1=1--",
        "1=2--",
        # Time-based blind
        "SLEEP(",
        "BENCHMARK(",
        "WAITFOR DELAY",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        # Standard variations
        "../",
        "..%2f",
        "..%5c",
        "..\\/",
        "%2e%2e%2f",
        "%2e%2e%5c",
        "..;/",
        "....//",     # Double encoding
        "..%252f",    # Double URL-encoded
        # Windows-specific
        "..\\",
        "..\\\\",
        # Unicode / alternative encoding
        "%c0%ae",     # UTF-8 encoded ..
        "%c1%1c",
        # Null byte injection
        "../%00",
        "..%00/",
    ]

    @staticmethod
    def analyze(telemetry: WebActivityWindowInput) -> Tuple[int, List[str], str]:
        """
        Executes full heuristic analysis on a telemetry window.
        
        Args:
            telemetry (WebActivityWindowInput): Data of the window to analyze
            
        Returns:
            Tuple[int, List[str], str]: (threat_score, indicators, reasoning)
                - threat_score: Score from 0-100
                - indicators: List of detected indicators
                - reasoning: Technical analysis summary
        """
        threat_score = 0
        indicators = []
        reasoning_parts = []
        
        source_ip = telemetry.source_ip
        total_requests = telemetry.total_requests
        
        # ============================================================
        # 1. USER-AGENT ANALYSIS
        # ============================================================
        ua_score, ua_indicators = ThreatHeuristics._analyze_user_agents(telemetry.user_agents_observed)
        if ua_score > 0:
            threat_score += ua_score
            indicators.extend(ua_indicators)
            reasoning_parts.append(f"Malicious User-Agent (+{ua_score})")
        
        # ============================================================
        # 2. SENSITIVE URI ANALYSIS
        # ============================================================
        uri_score, uri_indicators = ThreatHeuristics._analyze_sensitive_uris(telemetry.unique_uris_requested)
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
            telemetry.unique_uris_requested
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
    def _analyze_user_agents(user_agents: List[str]) -> Tuple[int, List[str]]:
        """Detects malicious User-Agents or scanning tools."""
        score = 0
        indicators = []
        
        for ua in user_agents:
            ua_lower = ua.lower()
            for keyword, ua_score in ThreatHeuristics.MALICIOUS_UA_KEYWORDS.items():
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
    def _analyze_sensitive_uris(uris: List[str]) -> Tuple[int, List[str]]:
        """Detects requests to sensitive paths."""
        score = 0
        indicators = []
        
        for uri in uris:
            uri_lower = uri.lower()
            for sensitive_path, path_score in ThreatHeuristics.SENSITIVE_URIS.items():
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
    def _analyze_injection_patterns(uris: List[str]) -> Tuple[int, List[str]]:
        """Detects SQL injection and path traversal patterns in URIs."""
        score = 0
        indicators = []
        
        for uri in uris:
            uri_lower = uri.lower()
            # URL decode to catch encoded patterns
            uri_decoded = uri_lower.replace("%27", "'").replace("%20", " ").replace("%2f", "/").replace("%5c", "\\")
            
            # Detect path traversal
            for pattern in ThreatHeuristics.PATH_TRAVERSAL_PATTERNS:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += 40  # Path traversal is critical
                    indicators.append(f"🔴 Path traversal pattern detected: {uri}")
                    break
            
            # Detect SQL injection
            for pattern in ThreatHeuristics.SQL_INJECTION_PATTERNS:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += 30  # SQL injection detection
                    indicators.append(f"🔴 SQL injection pattern detected: {uri}")
                    break
        
        return score, indicators

