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

        http_methods_json = json.dumps(data["distributions"]["http_methods"])
        response_codes_json = json.dumps(data["distributions"]["response_codes"])
        uris_json = json.dumps(data["distributions"]["top_10_uris"])
        user_agents_json = json.dumps(data["distributions"]["user_agents"])
        critical_payloads_json = json.dumps(data["critical_payload_features"])
        infra_context_json = json.dumps(data["infra_context"])
        security_state_features_json = json.dumps(data["security_state_features"])

        return f"""Analyze this HTTP activity window following your system instructions:

Source IP: {data["source_ip"]}
Window ID: {data["window_id"]}
Time Window: {data["time_window"]}
Duration: {data["duration_seconds"]} seconds

Total requests in window: {data["metrics"]["total_requests"]}
Unique URIs requested: {data["metrics"]["unique_uris"]}
Unique User-Agents observed: {data["metrics"]["unique_user_agents"]}
Average requests/second: {data["metrics"]["avg_rps"]}
404 Response Ratio: {data["metrics"]["error_404_ratio"]}

HTTP Methods used: {http_methods_json}
Observed response codes: {response_codes_json}
Requested URIs (top 10): {uris_json}
Observed User-Agents: {user_agents_json}
Critical payload features: {critical_payloads_json}
Infrastructure context: {infra_context_json}
Security state features: {security_state_features_json}

Historical context and recidivism:
{data["history"]}"""

    @staticmethod
    def build_optimized_json_prompt(telemetry: Any, history: List[Any]) -> str:
        """OPTIMIZED and minimalist Prompt (For Ollama with Modelfile)."""
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
