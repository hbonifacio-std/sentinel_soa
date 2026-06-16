"""Módulo de ingeniería y construcción de prompts analíticos para el Servidor MCP.

Se encarga de estructurar la plantilla base inyectando los datos de telemetría
recibidos para entregárselos al motor de inferencia LLM.
"""
import json
from typing import List, Any

class AnalysisPromptBuilder:
    """Clase especializada en la generación dinámica de directrices y prompts de ciberseguridad."""

    @staticmethod
    def _extract_telemetry_data(telemetry: Any, history: List[Any]) -> dict:
        """Helper interno para centralizar el parsing de telemetría y evitar duplicación."""
        formatted_history: str = "Ninguna alerta previa registrada para esta IP."
        if history:
            history_lines = []
            for h in history:
                # CORRECCIÓN: Nos aseguramos de castear h.window_id a str por si viene como UUID
                history_lines.append(
                    f"- Ventana {str(h.window_id)}: Nivel={h.threat_level}, Puntuación={h.threat_score}%, "
                    f"Fase={h.kill_chain_phase or 'N/A'}, Indicadores={len(h.indicators_found)}"
                )
            formatted_history = "\n".join(history_lines)

        user_agents_clean = [str(ua).replace('\n', ' ').strip() for ua in telemetry.user_agents_observed]
        total_requests = telemetry.total_requests
        error_404_count = telemetry.response_codes_distribution.get("404", 0)
        error_ratio = (error_404_count / total_requests * 100) if total_requests > 0 else 0

        return {
            # CORRECCIÓN: Forzamos que el window_id principal sea un string.
            # Esto arreglará tanto el JSON de Ollama como la inyección de texto en el prompt de Gemini.
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
            "history": formatted_history
        }

    @staticmethod
    def build_full_prompt(telemetry: Any, history: List[Any]) -> str:
        """Prompt COMPLETO con instrucciones de sistema incluidas (Específico para Gemini)."""
        data = AnalysisPromptBuilder._extract_telemetry_data(telemetry, history)

        http_methods_json = json.dumps(data["distributions"]["http_methods"])
        response_codes_json = json.dumps(data["distributions"]["response_codes"])
        uris_json = json.dumps(data["distributions"]["top_10_uris"])
        user_agents_json = json.dumps(data["distributions"]["user_agents"])

        return f"""Analiza la siguiente ventana de actividad HTTP de forma meticulosa y técnica:

════════════════════════════════════════════════════════════════════
DATOS GENERALES DE TELEMETRÍA
════════════════════════════════════════════════════════════════════
IP de origen: {data["source_ip"]}
Identificador de Ventana: {data["window_id"]}
Ventana temporal: {data["time_window"]}
Duración: {data["duration_seconds"]} segundos

════════════════════════════════════════════════════════════════════
MÉTRICAS ESTADÍSTICAS AGREGADAS
════════════════════════════════════════════════════════════════════
Total de solicitudes en la ventana: {data["metrics"]["total_requests"]}
URIs únicas solicitadas: {data["metrics"]["unique_uris"]}
User-Agents únicos observados: {data["metrics"]["unique_user_agents"]}
Promedio de solicitudes/segundo: {data["metrics"]["avg_rps"]}
Ratio de respuestas 404: {data["metrics"]["error_404_ratio"]}

════════════════════════════════════════════════════════════════════
DISTRIBUCIÓN DETALLADA DE SOLICITUDES (JSON Formatted)
════════════════════════════════════════════════════════════════════
Métodos HTTP utilizados: {http_methods_json}
Códigos de respuesta observados: {response_codes_json}
URIs solicitadas (primeras 10): {uris_json}
User-Agents observados: {user_agents_json}

════════════════════════════════════════════════════════════════════
CONTEXTO HISTÓRICO Y REINCIDENCIA
════════════════════════════════════════════════════════════════════
{data["history"]}

════════════════════════════════════════════════════════════════════
INDICADORES CLAVE A EVALUAR (Cyber Kill Chain)
════════════════════════════════════════════════════════════════════
[1] RECONOCIMIENTO - Escaneo y Enumeración:
    ✓ Presencia de herramientas de escaneo conocidas (nikto, nmap, sqlmap, etc.)
    ✓ Barrido sistemático de URIs sensibles (/admin, /wp-login, /.env, /.git, /etc/passwd)
    ✓ Solicitudes a rutas comúnmente enumeradas (backup, config, shell, etc.)
    ✓ Patrón de escaneo de vulns (paramspider, wpscan, dirbuster, etc.)

[2] ANOMALÍAS ESTADÍSTICAS:
    ✓ Ratio de errores 404 > 50% (indicativo de enumeración fallida)
    ✓ RPS anómalo (>10 solicitudes/segundo = automatización)
    ✓ Distribución de métodos HTTP inusual (múltiples DELETEs, TRACEs, etc.)
    ✓ Múltiples códigos 403 (Forbidden) acumulados

[3] PATRONES DE ATAQUE:
    ✓ Inyección SQL en parámetros (' OR '1'='1, UNION SELECT, etc.)
    ✓ Path traversal (../, %2e%2e%2f, ..%5c, etc.)
    ✓ Escape de directorio (shell.php, webshell, cmd.aspx, etc.)
    ✓ Parámetros sospechosos (?id=1' OR 1=1, etc.)

[4] VELOCIDAD Y VOLUMEN:
    ✓ Ráfaga de más de 20 solicitudes en <5 minutos desde una IP única
    ✓ Velocidad de solicitudes consistente (bot/scanner = patrón periódico)
    ✓ Baja variabilidad en timestamps entre solicitudes

════════════════════════════════════════════════════════════════════
SCHEMA JSON DE SALIDA REQUERIDO
════════════════════════════════════════════════════════════════════
Debes devolver un único objeto JSON que se ajuste estrictamente a las siguientes propiedades y tipos:

{{
  "window_id": "string (Usa exactamente el valor: {data['window_id']})",
  "threat_detected": boolean (true si se detectaron anomalías/ataques, false si todo es tráfico legítimo),
  "threat_level": "string (Debe ser uno de estos valores: 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
  "threat_score": integer (Un valor entero de 0 a 100),
  "kill_chain_phase": "string o null (Usa 'Reconnaissance', 'Weaponization' o null si threat_detected es false)",
  "indicators_found": ["string", "string"] (Lista de hallazgos técnicos específicos mapeados, o un array vacío si no hay ninguno),
  "reasoning_summary": "string (Síntesis técnica de tu análisis de máximo 100 palabras)",
  "recommendation": "string (Acción de mitigación sugerida inmediata, a corto plazo o de análisis profundo)"
}}

════════════════════════════════════════════════════════════════════
DIRECTRICES DE CORRELACIÓN SEMÁNTICA
════════════════════════════════════════════════════════════════════
1. Si threat_score >= 70 → threat_detected=true y threat_level es "HIGH" o "CRITICAL"
2. Si threat_score 40-69 → threat_detected=true y threat_level es "MEDIUM"
3. Si threat_score 20-39 → threat_detected puede ser true/false, threat_level es "LOW"
4. Si threat_score < 20  → threat_detected=false y threat_level es "NONE"

Genera la respuesta directamente en formato JSON estructurado. No incluyas bloques de código markdown de tipo ```json ni texto adicional fuera del objeto."""

    @staticmethod
    def build_optimized_json_prompt(telemetry: Any, history: List[Any]) -> str:
        """Prompt OPTIMIZADO y minimalista (Para Ollama con Modelfile)."""
        data = AnalysisPromptBuilder._extract_telemetry_data(telemetry, history)

        ollama_payload = {
            "target_window_id": data["window_id"], # Ahora hereda el string limpio de _extract_telemetry_data
            "source_ip": data["source_ip"],
            "time_context": {
                "range": data["time_window"],
                "duration_seconds": data["duration_seconds"]
            },
            "statistical_metrics": data["metrics"],
            "telemetry_distributions": data["distributions"],
            "historical_alerts_context": data["history"]
        }
        return f"Execute analysis on the following telemetry payload and return the mandated schema:\n{json.dumps(ollama_payload, ensure_ascii=False)}"