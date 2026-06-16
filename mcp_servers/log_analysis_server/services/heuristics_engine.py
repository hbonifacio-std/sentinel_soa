"""
Módulo de motor de heurísticas deterministas para análisis de amenazas.

Implementa análisis basado en reglas para detectar patrones de ataque sin depender
del LLM, proporcionando un baseline de confianza para el scoring de amenazas.
"""

import logging
from typing import Dict, List, Tuple, Any
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput

logger = logging.getLogger(__name__)


class ThreatHeuristics:
    """Motor de análisis heurístico para cálculo de puntuación de riesgo (0-100%)."""
    
    # Diccionarios de indicadores de amenaza
    MALICIOUS_UA_KEYWORDS = {
        # Herramientas de escaneo de vulnerabilidades
        "nikto": 30,        # ✅ AUMENTO: Nikto es un escanador muy específico
        "nmap": 25,
        "sqlmap": 35,       # ✅ AUMENTO: SQLmap es extremadamente peligroso
        "dirbuster": 25,
        "masscan": 20,
        "nessus": 20,
        "openvas": 20,
        "metasploit": 30,   # ✅ AUMENTO
        "burp": 15,         # Testing pero puede ser malicioso
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
        "scanner": 20,      # ✅ NUEVO: Genérico
        "bot": 8,           # Genérico, bajo riesgo
        "crawler": 3,       # Legítimo
        "spider": 3,        # Legítimo
        "httpx": 25,        # ✅ NUEVO: Herramienta de probing
        "subfinder": 20,    # ✅ NUEVO: Subdomain enumeration
    }
    
    SENSITIVE_URIS = {
        # Archivos del sistema operativo
        "/etc/passwd": 45,      # ✅ AUMENTO
        "/etc/shadow": 50,      # ✅ AUMENTO
        "/etc/sudoers": 50,     # ✅ NUEVO
        "/etc/hosts": 30,       # ✅ NUEVO
        "/etc/resolv.conf": 30, # ✅ NUEVO
        # Administrativos y paneles de control
        "/admin": 20,
        "/wp-admin": 25,        # ✅ AUMENTO
        "/wp-login": 18,
        "/admin/login.php": 25, # ✅ NUEVO
        "/administrator": 25,   # ✅ NUEVO
        "/cpanel": 30,          # ✅ NUEVO
        "/phpmyadmin": 35,      # ✅ NUEVO
        # Archivos de configuración
        "/.env": 40,            # ✅ AUMENTO
        "/.git": 35,            # ✅ AUMENTO
        "/.git/config": 45,     # ✅ AUMENTO
        "/config": 25,
        "/.env.local": 40,
        "/.env.dev": 40,        # ✅ NUEVO
        "/.env.prod": 40,       # ✅ NUEVO
        "/web.config": 30,      # ✅ AUMENTO
        "/.aws": 35,            # ✅ AUMENTO
        "/.ssh": 40,            # ✅ AUMENTO
        "/config.php": 30,      # ✅ NUEVO
        "/settings.json": 25,   # ✅ NUEVO
        # Archivos de respaldo y bases de datos
        "/backup": 20,
        "/backups": 20,         # ✅ NUEVO
        "/.sql": 30,
        "/.db": 30,
        "/database.sql": 35,    # ✅ NUEVO
        "/dump": 25,            # ✅ NUEVO
        # ASP.NET / PHP
        "/admin.php": 25,
        "/login.php": 12,
        "/shell.php": 50,       # ✅ AUMENTO
        "/webshell": 50,        # ✅ NUEVO
        "/cmd.php": 50,         # ✅ NUEVO
        "/php.ini": 40,         # ✅ AUMENTO
        "/.htaccess": 25,       # ✅ AUMENTO
        # Archivos de proyecto
        "/composer.json": 15,
        "/package.json": 12,
        "/pom.xml": 12,
        "/requirements.txt": 15, # ✅ NUEVO
        # Directorios peligrosos
        "/var/www": 20,         # ✅ NUEVO
        "/uploads": 15,         # ✅ NUEVO
        "/tmp": 15,             # ✅ NUEVO
    }
    
    SQL_INJECTION_PATTERNS = [
        # Patrones básicos
        "' OR '1'='1",
        "' OR 1=1",
        "' OR 'a'='a",
        "admin'--",
        "admin'#",
        # UNION-based
        "' UNION SELECT",
        "UNION SELECT",
        # URL-encoded variants para capturar %27
        "%27 OR %271%27=%271",
        "%27 OR 1=1",
        "%27 UNION SELECT",
        # Técnicas avanzadas
        "EXEC",
        "EXECUTE",
        "DROP TABLE",
        "INSERT INTO",
        "DELETE FROM",
        "SHUTDOWN",
        "WAITFOR",
        "xp_",  # Stored procedures SQL Server maliciosas
        # Boolean-based blind
        "1=1--",
        "1=2--",
        # Time-based blind
        "SLEEP(",
        "BENCHMARK(",
        "WAITFOR DELAY",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        # Variaciones estándar
        "../",
        "..%2f",
        "..%5c",
        "..\\/",
        "%2e%2e%2f",
        "%2e%2e%5c",
        "..;/",
        "....//",     # ✅ NUEVO: Double encoding
        "..%252f",    # ✅ NUEVO: Double URL-encoded
        # Windows-specific
        "..\\",
        "..\\\\",
        # Unicode / encoding alternative
        "%c0%ae",     # ✅ NUEVO: UTF-8 encoded ..
        "%c1%1c",
        # Null byte injection
        "../%00",
        "..%00/",
    ]

    @staticmethod
    def analyze(telemetry: WebActivityWindowInput) -> Tuple[int, List[str], str]:
        """
        Ejecuta análisis heurístico completo sobre una ventana de telemetría.
        
        Args:
            telemetry (WebActivityWindowInput): Datos de la ventana a analizar
            
        Returns:
            Tuple[int, List[str], str]: (threat_score, indicators, reasoning)
                - threat_score: Puntuación de 0-100
                - indicators: Lista de indicadores detectados
                - reasoning: Resumen técnico del análisis
        """
        threat_score = 0
        indicators = []
        reasoning_parts = []
        
        source_ip = telemetry.source_ip
        total_requests = telemetry.total_requests
        
        # ============================================================
        # 1. ANÁLISIS DE USER-AGENT
        # ============================================================
        ua_score, ua_indicators = ThreatHeuristics._analyze_user_agents(telemetry.user_agents_observed)
        if ua_score > 0:
            threat_score += ua_score
            indicators.extend(ua_indicators)
            reasoning_parts.append(f"User-Agent malicioso (+{ua_score})")
        
        # ============================================================
        # 2. ANÁLISIS DE URIs SENSIBLES
        # ============================================================
        uri_score, uri_indicators = ThreatHeuristics._analyze_sensitive_uris(telemetry.unique_uris_requested)
        if uri_score > 0:
            threat_score += uri_score
            indicators.extend(uri_indicators)
            reasoning_parts.append(f"URIs sensibles detectadas (+{uri_score})")
        
        # ============================================================
        # 3. ANÁLISIS DE CÓDIGOS DE RESPUESTA (404 Ratio)
        # ============================================================
        error_score, error_indicators = ThreatHeuristics._analyze_response_codes(
            telemetry.response_codes_distribution,
            total_requests
        )
        if error_score > 0:
            threat_score += error_score
            indicators.extend(error_indicators)
            reasoning_parts.append(f"Anomalía en códigos de respuesta (+{error_score})")
        
        # ============================================================
        # 4. ANÁLISIS DE VELOCIDAD (RPS anómalo)
        # ============================================================
        rps_score, rps_indicators = ThreatHeuristics._analyze_requests_per_second(
            telemetry.requests_per_second_avg,
            total_requests
        )
        if rps_score > 0:
            threat_score += rps_score
            indicators.extend(rps_indicators)
            reasoning_parts.append(f"RPS anómalo (+{rps_score})")
        
        # ============================================================
        # 5. ANÁLISIS DE DIVERSIDAD DE MÉTODOS HTTP
        # ============================================================
        method_score, method_indicators = ThreatHeuristics._analyze_http_methods(
            telemetry.http_methods_distribution
        )
        if method_score > 0:
            threat_score += method_score
            indicators.extend(method_indicators)
            reasoning_parts.append(f"Distribución HTTP anómala (+{method_score})")
        
        # ============================================================
        # 6. ANÁLISIS DE INYECCIÓN SQL / PATH TRAVERSAL
        # ============================================================
        injection_score, injection_indicators = ThreatHeuristics._analyze_injection_patterns(
            telemetry.unique_uris_requested
        )
        if injection_score > 0:
            threat_score += injection_score
            indicators.extend(injection_indicators)
            reasoning_parts.append(f"Patrones de inyección detectados (+{injection_score})")
        
        # ============================================================
        # 7. NORMALIZACIÓN Y LÍMITES (0-100)
        # ============================================================
        # Normalizar: suma escalada y asimetría
        threat_score = min(100, int(threat_score))
        
        # Generar reasoning sintético
        reasoning = f"Análisis heurístico de {source_ip}: "
        if reasoning_parts:
            reasoning += "; ".join(reasoning_parts) + "."
        else:
            reasoning += "No se detectaron indicadores de amenaza."
        
        return threat_score, indicators, reasoning

    @staticmethod
    def _analyze_user_agents(user_agents: List[str]) -> Tuple[int, List[str]]:
        """Detecta User-Agents maliciosos o herramientas de escaneo."""
        score = 0
        indicators = []
        
        for ua in user_agents:
            ua_lower = ua.lower()
            for keyword, ua_score in ThreatHeuristics.MALICIOUS_UA_KEYWORDS.items():
                if keyword in ua_lower:
                    score += ua_score
                    # ✅ MEJORA: Mensajes más específicos y dicientes
                    tool_name = keyword.upper()
                    if "nikto" in keyword:
                        indicators.append(f"🔴 Herramienta de escaneo detectada: {tool_name} (Nikto Web Scanner - Enumeración de vulnerabilidades)")
                    elif "sqlmap" in keyword:
                        indicators.append(f"🔴 Herramienta especializada detectada: {tool_name} (SQL Injection Tester - Ataque directo a BD)")
                    elif "metasploit" in keyword:
                        indicators.append(f"🔴 Framework de explotación detectado: {tool_name} (Metasploit - Herramienta ofensiva)")
                    elif "nmap" in keyword:
                        indicators.append(f"🔴 Herramienta de reconocimiento detectada: {tool_name} (Network Mapper - Mapeo de puertos/servicios)")
                    else:
                        indicators.append(f"🟠 User-Agent sospechoso: {ua} (Herramienta de testing/scanning: {tool_name})")
                    break
        
        return score, indicators

    @staticmethod
    def _analyze_sensitive_uris(uris: List[str]) -> Tuple[int, List[str]]:
        """Detecta solicitudes a rutas sensibles."""
        score = 0
        indicators = []
        
        for uri in uris:
            uri_lower = uri.lower()
            for sensitive_path, path_score in ThreatHeuristics.SENSITIVE_URIS.items():
                if sensitive_path in uri_lower:
                    score += path_score
                    indicators.append(f"Solicitud a ruta sensible: {uri}")
                    break
        
        return score, indicators

    @staticmethod
    def _analyze_response_codes(response_dist: Dict[str, int], total: int) -> Tuple[int, List[str]]:
        """Analiza la distribución de códigos de respuesta para detectar enumeración."""
        score = 0
        indicators = []
        
        # Contar 404s
        code_404_count = response_dist.get("404", 0)
        if total > 0:
            error_ratio = code_404_count / total
            
            # Si más del 60% son 404, es probable enumeración
            if error_ratio > 0.6:
                score += 30
                indicators.append(f"Alto ratio de errores 404: {error_ratio:.1%} ({code_404_count}/{total})")
            elif error_ratio > 0.4:
                score += 15
                indicators.append(f"Ratio de errores 404 moderado: {error_ratio:.1%}")
        
        # Contar otros códigos de error (5xx)
        code_5xx_count = sum(v for k, v in response_dist.items() if k.startswith("5"))
        if code_5xx_count > 3:
            score += 10
            indicators.append(f"Múltiples errores del servidor (5xx): {code_5xx_count}")
        
        # Contar accesos denegados (403)
        code_403_count = response_dist.get("403", 0)
        if code_403_count > 5:
            score += 10
            indicators.append(f"Múltiples accesos denegados (403): {code_403_count}")
        
        return score, indicators

    @staticmethod
    def _analyze_requests_per_second(rps: float, total_requests: int) -> Tuple[int, List[str]]:
        """Detecta velocidades de solicitud anómalas (escaneo rápido o lento)."""
        score = 0
        indicators = []
        
        # RPS elevado (más de 10 req/s es sospechoso para un usuario normal)
        if rps > 10.0:
            score += 25
            indicators.append(f"RPS elevado detectado: {rps:.2f} solicitudes/segundo")
        elif rps > 5.0:
            score += 10
            indicators.append(f"RPS moderadamente alto: {rps:.2f} solicitudes/segundo")
        
        # Muchas solicitudes en una ventana corta
        if total_requests > 50 and rps < 5.0:
            score += 15
            indicators.append(f"Ráfaga de {total_requests} solicitudes en ventana temporal corta")
        
        return score, indicators

    @staticmethod
    def _analyze_http_methods(methods_dist: Dict[str, int]) -> Tuple[int, List[str]]:
        """Detecta uso inusual de métodos HTTP."""
        score = 0
        indicators = []
        
        suspicious_methods = ["DELETE", "TRACE", "CONNECT", "OPTIONS"]
        for method in suspicious_methods:
            if methods_dist.get(method, 0) > 0:
                score += 10
                indicators.append(f"Método HTTP sospechoso: {method} ({methods_dist[method]} solicitudes)")
        
        # POST sin GET es raro
        post_count = methods_dist.get("POST", 0)
        get_count = methods_dist.get("GET", 0)
        if post_count > 5 and get_count == 0:
            score += 15
            indicators.append(f"Distribución inusual: {post_count} POSTs sin GETs")
        
        return score, indicators

    @staticmethod
    def _analyze_injection_patterns(uris: List[str]) -> Tuple[int, List[str]]:
        """Detecta patrones de inyección SQL y path traversal en URIs."""
        score = 0
        indicators = []
        
        for uri in uris:
            uri_lower = uri.lower()
            # URL decode para atrapar patrones codificados
            uri_decoded = uri_lower.replace("%27", "'").replace("%20", " ").replace("%2f", "/").replace("%5c", "\\")
            
            # Detectar path traversal
            for pattern in ThreatHeuristics.PATH_TRAVERSAL_PATTERNS:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += 40  # ✅ AUMENTO: Path traversal es crítico
                    indicators.append(f"🔴 Patrón de path traversal detectado: {uri}")
                    break
            
            # Detectar inyección SQL
            for pattern in ThreatHeuristics.SQL_INJECTION_PATTERNS:
                if pattern.lower() in uri_lower or pattern.lower() in uri_decoded:
                    score += 30  # ✅ AUMENTO: SQL injection detection
                    indicators.append(f"🔴 Patrón de inyección SQL detectado: {uri}")
                    break
        
        return score, indicators

