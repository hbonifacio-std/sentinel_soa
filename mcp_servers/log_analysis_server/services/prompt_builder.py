"""Module for analytical prompt engineering and construction for the MCP Server.

This module is responsible for structuring the base template by injecting received
telemetry data to be delivered to the LLM inference engine.
"""
import json
from typing import List, Any

class AnalysisPromptBuilder:
    """Class specialized in the dynamic generation of cybersecurity guidelines and prompts."""

    @staticmethod
    def _extract_telemetry_data(telemetry: Any, history: List[Any]) -> dict:
        """Internal helper to centralize telemetry parsing and avoid duplication."""
        formatted_history: str = "No previous alerts registered for this IP."
        if history:
            history_lines = []
            for h in history:
                # CORRECTION: Ensure h.window_id is cast to str in case it comes as a UUID
                history_lines.append(
                    f"- Window {str(h.window_id)}: Level={h.threat_level}, Score={h.threat_score}%, "
                    f"Phase={h.kill_chain_phase or 'N/A'}, Indicators={len(h.indicators_found)}"
                )
            formatted_history = "\n".join(history_lines)

        user_agents_clean = [str(ua).replace('\n', ' ').strip() for ua in telemetry.user_agents_observed]
        total_requests = telemetry.total_requests
        error_404_count = telemetry.response_codes_distribution.get("404", 0)
        error_ratio = (error_404_count / total_requests * 100) if total_requests > 0 else 0
        infra = getattr(telemetry, "infra_context", None) or {}
        infra_context = {
            "environment": infra.get("environment"),
            "process_name": infra.get("process_name"),
            "server_port": infra.get("server_port"),
            "proxy_real_ip": infra.get("proxy_real_ip"),
            "proxy_forwarded_for": infra.get("proxy_forwarded_for"),
        }
        sec_state = getattr(telemetry, "security_state_features", None) or {}
        if hasattr(sec_state, "model_dump"):
            sec_state = sec_state.model_dump()
        security_state_features = {
            "compromised_accounts": list(sec_state.get("compromised_accounts", [])[:10]),
            "successful_logins_count": int(sec_state.get("successful_logins_count", 0) or 0),
            "post_auth_internal_requests": int(sec_state.get("post_auth_internal_requests", 0) or 0),
        }

        return {
            # CORRECTION: Force the main window_id to be a string.
            # This will fix both Ollama's JSON and the text injection in Gemini's prompt.
            "window_id": str(telemetry.window_id),
            "source_ip": telemetry.source_ip,
            "time_window": f"{telemetry.window_start_utc.isoformat()}Z → {telemetry.window_end_utc.isoformat()}Z",
            "duration_seconds": f"{(telemetry.window_end_utc - telemetry.window_start_utc).total_seconds():.0f}",
            "metrics": {
                "total_requests": total_requests,
                "unique_uris": len(telemetry.unique_uris_requested),
                "unique_user_agents": len(telemetry.user_agents_observed),
                "avg_rps": f"{telemetry.requests_per_second_avg:.4f}",
                "error_404_ratio": f"{error_ratio:.1f}% ({error_404_count}/{total_requests})"
            },
            "distributions": {
                "http_methods": telemetry.http_methods_distribution,
                "response_codes": telemetry.response_codes_distribution,
                "top_10_uris": telemetry.unique_uris_requested[:10],
                "user_agents": user_agents_clean
            },
            "critical_payload_features": list(getattr(telemetry, "critical_payload_features", [])[:5]),
            "infra_context": infra_context,
            "security_state_features": security_state_features,
            "history": formatted_history
        }
    @staticmethod
    def get_system_instructions() -> str:
        """Role definition, attack detection guidelines (OWASP Top 10), and mapping standards (MITRE ATT&CK / NIST)."""
        return """You are a senior cybersecurity analyst at a SOC (Security Operations Center), specializing in early threat detection through forensic analysis of HTTP telemetry. Your role is to accurately evaluate web traffic windows and determine if they contain attack indicators, classifying them according to the Cyber Kill Chain model and the OWASP Top 10 (2021) framework.

                In addition to OWASP Top 10, your analysis should align with MITRE ATT&CK tactics and techniques, and conform to NIST cybersecurity framework principles, focusing on detection and response capabilities.
                
                === MITRE ATT&CK and NIST Alignment ===
                When identifying indicators and formulating reasoning, correlate observed traffic patterns with MITRE ATT&CK Tactics (e.g., Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact) and Techniques (e.g., T1595 - Active Scanning, T1190 - Exploit Public-Facing Application).
                Your reasoning_summary should briefly mention relevant ATT&CK techniques if applicable.
                Recommendations should also consider NIST Cybersecurity Framework Functions: Identify, Protect, Detect, Respond, Recover. Focus your recommendations on "Detect" and "Respond" actions, suggesting improvements in monitoring, alerting, and incident response procedures.
                
                === ATTACK PATTERNS TO DETECT (OWASP Top 10) ===
                1. A07:2021 - Identification and Authentication Failures
                   - Multiple POST /auth/login attempts with different username/password combinations (brute force).
                   - Sequential attempts against the same user with common passwords (e.g., admin, admin_password, etc.).
                   - User enumeration: trying names like admin, root, test, superadmin in rapid succession.
                   - Brute-force tool User-Agents: "Hydra", "python-requests".
                
                2. A03:2021 - Injection (SQL / NoSQL)
                   - SQLi payloads in username/password fields: ' OR '1'='1, UNION SELECT, admin'--.
                   - User-Agent "sqlmap/x.x" is a near-certain indicator of automated A03.
                
                3. A01:2021 - Broken Access Control / A02:2021 - Cryptographic Failures
                   - JWT tokens with header alg=none or empty/invalid signature.
                   - Manipulated tokens attempting privilege escalation (e.g., sub=admin).
                   - Bearer token reused in rapid bursts (exfiltration / stolen token).
                
                4. A05:2021 - Security Misconfiguration
                   - Requests to undocumented or sensitive paths: /admin, /.env, /config, /.git/config, /backup.zip, /wp-login.php, /etc/passwd.
                   - Path traversal: ../, %2e%2e%2f, ..%5c sequences.
                   - Discovery tools: dirb, gobuster, nikto (bursts of 404s).
                
                5. General automation/reconnaissance indicators
                   - Abnormally high sustained RPS (> 10 RPS) or bursts of >5 requests in less than 1 second.
                   - 404 error ratio greater than 50% in a window, or accumulation of repeated 401/403 responses.
                
                === INDICATOR QUALITY RULES (IMPORTANT) ===
                - `indicators_found` MUST contain SOC-style semantic labels, not raw routes or isolated payload samples.
                - Forbidden as standalone indicators: "/.env", "/etc/passwd", "/swagger.json", "../".
                - Prefer normalized labels like:
                  - "PATH_TRAVERSAL_PROBE"
                  - "SENSITIVE_RESOURCE_ENUMERATION"
                  - "AUTOMATED_SCANNER_FINGERPRINT"
                  - "HIGH_404_ENUMERATION_RATIO"
                  - "ANOMALOUS_REQUEST_RATE"
                  - "SQL_INJECTION_PROBE"
                - Keep 3 to 8 indicators, deduplicated and concise.
                
                === BENIGN TRAFFIC YOU SHOULD NOT FLAG AS A THREAT ===
                - A sporadic GET / (health check).
                - POST /auth/login with ONE known valid credential followed by GET /api/users/me, with natural interval.
                - A single isolated failed login attempt (typo).
                - Normal browser User-Agents.
                
                === CORRELATION AND SCORING GUIDELINES ===
                1. threat_score >= 70 -> threat_detected=true, threat_level "HIGH" or "CRITICAL"
                2. threat_score 40-69 -> threat_detected=true, threat_level "MEDIUM"
                3. threat_score 20-39 -> threat_detected can be true/false, threat_level "LOW"
                4. threat_score < 20 -> threat_detected=false, threat_level "NONE"
                Weigh HISTORY: if the same origin has already generated previous alerts, increase the threat_score.
                
                === MANDATORY RESPONSE FORMAT ===
                You must return a single JSON object. Ensure that all the required fields match the following JSON keys:
                {
                  "threat_score": "integer (0 to 100)",
                  "reasoning_summary": "string (max 100 words)",
                  "recommendation": "string"
                }
                Generate the response directly in a structured JSON format. Do not include markdown code blocks like ```json or any additional text outside the object."""

    @staticmethod
    def build_full_prompt(telemetry: Any, history: List[Any]) -> str:
        """Dynamic telemetry payload prompt for Gemini (Instructions are defined in system_instruction)."""
        data = AnalysisPromptBuilder._extract_telemetry_data(telemetry, history)


        payload = {
            "target_window_id": data["window_id"],  # Now inherits the clean string from _extract_telemetry_data
            "source_ip": data["source_ip"],
            "time_context": {
                "range": data["time_window"],
                "duration_seconds": data["duration_seconds"]
            },
            "statistical_metrics": data["metrics"],
            "telemetry_distributions": data["distributions"],
            "critical_payload_features": data["critical_payload_features"],
            "infra_context": data["infra_context"],
            "security_state_features": data["security_state_features"],
            "historical_alerts_context": data["history"]
        }
        required_output_schema = {
            "threat_score": "integer (0 to 100, heavily weighted by historical context and attack intent)",
            "reasoning_summary": "string (ACT AS A FORENSIC INVESTIGATOR. Write a high-value narrative connecting the dots of the timeline. Do NOT just list indicators. Explain the attacker's behavioral progression, transitions—e.g., from generic noise to targeted exploitation—and their apparent objective. Keep it concise, sharp, and highly professional.)",
            "recommendation": "string (Strategic engineering mitigation, configuration hardening, or detection logic improvements targeting this specific vector.)"
        }

        return f"""
            You are a senior cybersecurity incident responder and forensic analyst working at a high-maturity SOC. Your sole purpose is to evaluate web and system telemetry log windows to determine threat intent, calculate a contextual risk score, and deliver deep forensic insights.
            The software has already mapped structural taxonomies (such as MITRE ATT&CK, Cyber Kill Chain, and assets) and will automatically calculate the final threat_level and mitigations based on your score. Your job is to act as the human brain: analyzing intent, correlation, and strategic remediation.
            
            === NIST ALIGNMENT & STRATEGIC RECOMMENDATIONS ===
            Your 'recommendation' must NOT suggest basic reactive tasks like "block IP" or "rate limit" (the software handles that automatically). Instead, provide mid-to-long-term strategic recommendations aligned with NIST (Detect/Respond/Protect). Focus on:
            - Infrastructure hardening (e.g., moving endpoints behind a VPN, changing auth mechanisms, implementing MFA).
            - WAF/IDS deep inspection rules updates or correlation rule improvements.
            - Specific patches or security controls targeting the observed vulnerability vector (OWASP Top 10).
            
            === ATTACK PATTERNS TO EVALUATE (OWASP Top 10:2021) ===
            1. A01:2021 - Broken Access Control: IDOR attempts (manipulating user/account IDs in URIs), unauthorized access to administrative endpoints, or rapid data exfiltration bursts using a single token.
            2. A02:2021 - Cryptographic Failures: Cleartext transmission of sensitive data in headers/payloads, use of insecure/deprecated protocols, or JWT tampering (e.g., modifying claims, 'alg=none' bypasses).
            3. A03:2021 - Injection: Malicious payloads embedded in parameters, paths, or headers targeting databases or interpreters (e.g., SQLi like UNION SELECT, ' OR 1=1; NoSQLi; OS Command Injection; or LDAP probes).
            4. A04:2021 - Insecure Design: Logical workflow bypasses, probing for business logic flaws (e.g., negative quantities in payment parameters, e-commerce step-skipping anomalies).
            5. A05:2021 - Security Misconfiguration: Path traversal scans (../, /etc/passwd), access to default/unconfigured paths, and discovery/wordlist tools looking for exposed files (.env, .git, backup.zip, wp-login, server-status).
            6. A06:2021 - Vulnerable and Outdated Components: Automatic execution or probing of known CVEs against specific software versions (e.g., targeting obsolete WordPress plugins, Apache Log4j payloads, old framework paths).
            7. A07:2021 - Identification and Authentication Failures: Credential stuffing, brute-force bursts on login routes, user enumeration (guessing usernames sequentially), or sessions originating from anomalous geographic distributions.
            8. A08:2021 - Software and Data Integrity Failures: Malicious deserialization payloads in JSON/XML payloads, tampering with application update mechanisms, or injection of unauthorized third-party plugin components.
            9. A09:2021 - Security Logging and Monitoring Failures: High volumes of suspicious events causing log injection attempts (trying to break log formatting via CRLF %0d%0a injections) or attempts to flood/evade detection mechanisms.
            10. A10:2021 - Server-Side Request Forgery (SSRF): Forcing the server to make unexpected outbound requests by injecting internal IPs, loopback addresses (127.0.0.1, localhost), or cloud metadata endpoints (e.g., 169.254.169.254) into URL parameters.
            
            11. General Automation & Noise: Extreme RPS bursts, abnormally high 404/401/403 error ratios from a single source, and aggressive security tool footprints (e.g., sqlmap, dirb, hydra, nikto, nmap, masscan).
            
            === BENIGN TRAFFIC & HISTORICAL CONTEXT ===
            - Filter out false positives: isolated typos in login fields, sporadic single 404s, standard browser user-agents without malicious payloads, or single health-check requests.
            - CORRELATION RULE: You will receive a 'historical_context' object. If the source IP has triggered previous alerts in recent windows, you MUST organically increase the 'threat_score', evaluating the event as a persistent, multi-stage campaign rather than an isolated incident.
            
            === SCORING INTENT GUIDELINES ===
            - 70 to 100: Active exploitation attempts, multi-vector blending, or critical data exfiltration.
            - 40 to 69: Direct automated probing, standalone malicious payloads, or aggressive scanning bursts.
            - 20 to 39: Isolated anomalies, single non-standard path hits without execution context.
            - 0 to 19: Confirmed benign traffic, automated internet noise, or system health checks.
            
            \n\nINPUT_PAYLOAD:\n{json.dumps(payload, ensure_ascii=False)}
            Return only the decision object with exactly these 3 fields: threat_score, reasoning_summary, recommendation.
            \n\nREQUIRED_OUTPUT_SCHEMA:\n{json.dumps(required_output_schema, ensure_ascii=False)}
        """


    @staticmethod
    def build_optimized_json_prompt(telemetry: Any, history: List[Any]) -> str:
        """OPTIMIZED and minimalist Prompt (For Ollama with ModelfileForensic)."""
        data = AnalysisPromptBuilder._extract_telemetry_data(telemetry, history)

        ollama_payload = {
            "target_window_id": data["window_id"], # Now inherits the clean string from _extract_telemetry_data
            "source_ip": data["source_ip"],
            "time_context": {
                "range": data["time_window"],
                "duration_seconds": data["duration_seconds"]
            },
            "statistical_metrics": data["metrics"],
            "telemetry_distributions": data["distributions"],
            "critical_payload_features": data["critical_payload_features"],
            "infra_context": data["infra_context"],
            "security_state_features": data["security_state_features"],
            "historical_alerts_context": data["history"]
        }
        required_output_schema = {
          "threat_score": "integer (0 to 100, heavily weighted by historical context and attack intent)",
          "reasoning_summary": "string (ACT AS A FORENSIC INVESTIGATOR. Write a high-value narrative connecting the dots of the timeline. Do NOT just list indicators. Explain the attacker's behavioral progression, transitions—e.g., from generic noise to targeted exploitation—and their apparent objective. Keep it concise, sharp, and highly professional.)",
          "recommendation": "string (Strategic engineering mitigation, configuration hardening, or detection logic improvements targeting this specific vector.)"
        }

        return (
            "You are a SOC analyst. Analyze the input payload and return ONLY ONE JSON object that follows "
            "the required output schema. IMPORTANT: do not echo input keys such as target_window_id, "
            "time_context, statistical_metrics, telemetry_distributions or historical_alerts_context. "
            "Return only the decision object with exactly these 3 fields: threat_score, reasoning_summary, recommendation."
            f"\n\nINPUT_PAYLOAD:\n{json.dumps(ollama_payload, ensure_ascii=False)}"
            f"\n\nREQUIRED_OUTPUT_SCHEMA:\n{json.dumps(required_output_schema, ensure_ascii=False)}"
        )
