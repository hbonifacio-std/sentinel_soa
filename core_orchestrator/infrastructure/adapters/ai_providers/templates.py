"""Module for analytical prompt engineering and construction for the MCP Server.

DEPRECATED: This module is maintained for backward compatibility. New code should use
`prompt_factory.build_web_activity_prompt()` and `prompt_factory.build_forensic_prompt()`
instead. For system instructions, use the ` system_instructions ` module.

=== LLM RECOMMENDATIONS vs DETERMINISTIC HEURISTICS (Read This!) ===

**LLM Output Fields**:
- `threat_score`: Human-interpretable risk score (0-100), computed by the LLM based on attack pattern recognition
- `reasoning_summary`: Narrative explanation of why this window triggered an alert (max 100 words)
- `recommendation`: Strategic, mid-to-long-term mitigation actions (e.g., "Implement MFA", "Update WAF rules")

These three fields form the LLM's decision. They are:
✓ Strategic (focused on systemic improvements, not immediate band-aids)
✓ Contextual (incorporate historical alerts, infrastructure state, attack patterns)
✓ Human-reviewed-ready (safe for SOC analysts to read and act upon)

**Heuristic Scoring** (separate system):
The deterministic heuristics in `analyze_activity/heuristics_engine.py` compute a separate
`score` and `indicators_found` list based on:
- Statistical anomalies (RPS spikes, 404 ratio, response code distribution)
- Known attack pattern signatures (SQL injection attempts, path traversal, brute force)
- Payload inspection (malicious User-Agent strings, suspicious headers)

Heuristic results are:
✓ Immediate (no LLM latency, deterministic)
✓ Observable (clear rules, auditable decision paths)
✓ Tactical (focused on fast threat response)

**How They Integrate**:
1. Telemetry arrives → Heuristics compute indicators + score
2. Heuristic score passed to LLM as context
3. LLM outputs: threat_score, reasoning, recommendation
4. Backend merges:
   - Uses higher of (heuristic_score, llm_threat_score) as canonical threat_score
   - Uses LLM's reasoning_summary verbatim
   - Uses LLM's recommendation for strategic guidance
   - Uses heuristic indicators + suggested_mitigations for immediate actions

Maintainers: When changing the semantic of these fields, update docstrings in
prompt_factory.py as well to keep them in sync.
"""
import json
import warnings
from typing import List, Any

from mcp_servers.log_analysis_server.services.system_instructions import (
    get_analysis_system_instructions,
)


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
        """Role definition, attack detection guidelines (OWASP Top 10), and mapping standards (MITRE ATT&CK / NIST).

        DEPRECATED: Use `system_instructions.get_analysis_system_instructions()` instead.
        This method will be removed in a future version.
        """
        warnings.warn(
            "AnalysisPromptBuilder.get_system_instructions() is deprecated. "
            "Use system_instructions.get_analysis_system_instructions() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return get_analysis_system_instructions()

    @staticmethod
    def build_full_prompt(telemetry: Any, history: List[Any]) -> str:
        """Dynamic telemetry payload prompt for Gemini (Instructions are defined in system_instruction).

        DEPRECATED: Use `prompt_factory.build_web_activity_prompt()` with provider_name='gemini' instead.
        This method will be removed in a future version.
        """
        warnings.warn(
            "AnalysisPromptBuilder.build_full_prompt() is deprecated. "
            "Use prompt_factory.build_web_activity_prompt(telemetry, history, 'gemini') instead.",
            DeprecationWarning,
            stacklevel=2
        )
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
        """OPTIMIZED and minimalist Prompt (For Ollama with ModelfileForensic).

        DEPRECATED: Use `prompt_factory.build_web_activity_prompt()` with provider_name='ollama' instead.
        This method will be removed in a future version.
        """
        warnings.warn(
            "AnalysisPromptBuilder.build_optimized_json_prompt() is deprecated. "
            "Use prompt_factory.build_web_activity_prompt(telemetry, history, 'ollama') instead.",
            DeprecationWarning,
            stacklevel=2
        )
        data = AnalysisPromptBuilder._extract_telemetry_data(telemetry, history)

        ollama_payload = {
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

        return (
            "You are a SOC analyst. Analyze the input payload and return ONLY ONE JSON object that follows "
            "the required output schema. IMPORTANT: do not echo input keys such as target_window_id, "
            "time_context, statistical_metrics, telemetry_distributions or historical_alerts_context. "
            "Return only the decision object with exactly these 3 fields: threat_score, reasoning_summary, recommendation."
            f"\n\nINPUT_PAYLOAD:\n{json.dumps(ollama_payload, ensure_ascii=False)}"
            f"\n\nREQUIRED_OUTPUT_SCHEMA:\n{json.dumps(required_output_schema, ensure_ascii=False)}"
        )