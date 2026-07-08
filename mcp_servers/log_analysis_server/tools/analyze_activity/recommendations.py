"""Mitigation recommendation generation based on threat level and indicators."""

from typing import List


def generate_recommendation(threat_level: str, source_ip: str, indicators: list) -> str:
    """Generates a mitigation recommendation based on the threat level and specific indicators.

    Args:
        threat_level: One of CRITICAL, HIGH, MEDIUM, LOW, NONE.
        source_ip: The source IP address.
        indicators: List of detected threat indicators.

    Returns:
        Human-readable recommendation text with action levels.
    """

    # Analyze specific indicators for more descriptive recommendations
    has_sql_injection = any("SQL" in ind for ind in indicators)
    has_path_traversal = any("path traversal" in ind.lower() for ind in indicators)
    has_scanner = any("Scanner" in ind or "scanning" in ind.lower() for ind in indicators)
    has_admin_access = any("admin" in ind.lower() for ind in indicators)
    has_shell = any("shell" in ind.lower() or "webshell" in ind.lower() for ind in indicators)

    if threat_level == "CRITICAL":
        recommendation = (
            f"🔴 **CRITICAL LEVEL - IMMEDIATE ACTION REQUIRED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Level 1 (Immediately - 0-5 minutes):**\n"
        )
        if has_shell:
            recommendation += "• BLOCK IMMEDIATELY in WAF/Firewall. Evidence of webshell attempt detected.\n"
        elif has_sql_injection:
            recommendation += "• BLOCK IMMEDIATELY in WAF/Firewall. SQL injection attack in progress.\n"
        elif has_path_traversal:
            recommendation += "• BLOCK IMMEDIATELY in WAF/Firewall. Attempt to access sensitive system files.\n"
        else:
            recommendation += f"• BLOCK IMMEDIATELY IP {source_ip} at all entry points (WAF/Firewall).\n"

        recommendation += (
            "• Verify if the attack was successful (check 200/500 response codes).\n"
            "• Prepare incident response team.\n\n"
            "**Level 2 (In parallel - 5-30 minutes):**\n"
            "• Run forensic analysis: review access logs from the last 24 hours.\n"
            "• Correlate with other suspicious IPs or similar patterns.\n"
            "• Verify server file integrity (web.config, .env, etc.).\n"
            "• Review file modification events in ACLs.\n\n"
            "**Level 3 (Escalation - 30+ minutes):**\n"
            "• Escalate to cybersecurity team and IT leadership.\n"
            "• Consider server snapshot for malware analysis.\n"
            "• Begin potential compromise investigation.\n"
        )
    elif threat_level == "HIGH":
        recommendation = (
            f"🟠 **HIGH LEVEL - URGENT ACTION RECOMMENDED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Level 1 (Immediately):**\n"
            f"• Temporarily block IP {source_ip} in WAF/Firewall for 24 hours.\n"
        )
        if has_scanner:
            recommendation += "• Implement more aggressive rate-limiting. Enumeration/scanning pattern detected.\n"
        if has_admin_access:
            recommendation += "• Urgently review access to administrative panels.\n"
        recommendation += (
            "\n**Level 2 (Next 2 hours):**\n"
            "• Audit all resources requested by this IP.\n"
            "• Review logs from the last 24 hours for this source.\n"
            "• Verify that administrative endpoints are protected (authentication + 2FA).\n"
            "• Confirm that WAF rules are active for SQL injection/XSS.\n\n"
            "**Level 3 (Ongoing monitoring):**\n"
            "• Monitor future behavior of this IP for the next 7 days.\n"
            "• Consider permanent block if attempts persist.\n"
        )
    elif threat_level == "MEDIUM":
        recommendation = (
            f"🟡 **MEDIUM LEVEL - MONITORING RECOMMENDED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Recommended Actions:**\n"
            f"• Increase monitoring of IP {source_ip}. Suspicious behavior detected.\n"
            f"• Implement rate-limiting on web endpoints.\n"
            f"• Review recent logs (last 6 hours).\n"
            f"• Consider temporary 24-48 hour block if pattern repeats.\n"
            f"• Verify that WAF/IDS is capturing events and alerting correctly.\n"
        )
    else:
        recommendation = (
            "🟢 **LOW/BENIGN LEVEL**\n"
            "Traffic classified as benign or very low suspicion. "
            "Continue with standard routine monitoring.\n"
            "No immediate action required.\n"
        )

    return recommendation
