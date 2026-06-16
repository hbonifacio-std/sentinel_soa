"""
Script de Simulación de Ataque con Técnicas de Evasión Avanzadas.
Diseñado para evaluar la robustez del Agente IA contra bypass de WAF/Firmas.

Técnicas de evasión incluidas:
1. User-Agent Spoofing (El atacante finge ser un navegador Chrome legítimo)
2. URL/Hex Encoding (Ofuscación de caracteres para evadir expresiones regulares)
3. Tráfico "Bajo y Lento" (Mezcla de peticiones benignas y malignas desde la misma IP)
4. Falsos Positivos Complejos (Comportamiento que parece ataque pero es legítimo)
"""
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
import asyncio
import httpx
import json
from datetime import datetime, timezone

BASE_URL = "http://localhost:8000/api/v1/telemetry"

# Obtenemos la hora actual del sistema en formato Nginx estándar
now_nginx = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")

# CHROME_UA actuará como nuestro User-Agent camuflado para los ataques
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ==============================================================================
# ESCENARIOS DE EVASIÓN AVANZADOS
# ==============================================================================

# 🧪 ESCENARIO 1: Ataque "Low & Slow" (Bajo y Lento) + User-Agent Spoofing
# El atacante (10.0.0.99) navega normalmente por el sitio para diluir sus métricas,
# pero introduce payloads dañinos camuflados con un UA de un navegador común.
LOW_AND_SLOW_LOGS = [
    f'10.0.0.99 - - [{now_nginx}] "GET /home HTTP/1.1" 200 8500 "-" "{CHROME_UA}"',
    f'10.0.0.99 - - [{now_nginx}] "GET /products?category=electronics HTTP/1.1" 200 12400 "-" "{CHROME_UA}"',
    f'10.0.0.99 - - [{now_nginx}] "GET /etc/passwd HTTP/1.1" 404 230 "-" "{CHROME_UA}"',
    # <-- Ataque 1 (Path Traversal)
    f'10.0.0.99 - - [{now_nginx}] "GET /assets/banner.jpg HTTP/1.1" 200 45000 "-" "{CHROME_UA}"',
    f'10.0.0.99 - - [{now_nginx}] "GET /vulnerabilities/sqli/?id=%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 500 230 "-" "{CHROME_UA}"'
    # <-- Ataque 2 (SQLi Complejo)
]

# 🧪 ESCENARIO 2: Ofuscación Extrema de Payloads (URL Encoding Doble y Hex)
# El atacante (10.0.0.77) intenta evadir expresiones regulares clásicas codificando la URI.
# %2e%2e%2f es la codificación de ../ (Path Traversal)
# %27 es la comilla simple para SQL Injection
OFUSCATED_ATTACK_LOGS = [
    f'10.0.0.77 - - [{now_nginx}] "GET /%2e%2e%2f%2e%2e%2f%2e%2e%2fwin.ini HTTP/1.1" 404 230 "-" "{CHROME_UA}"',
    f'10.0.0.77 - - [{now_nginx}] "POST /api/search HTTP/1.1" 500 410 "search=item%27%20OR%20%271%27=%271" "{CHROME_UA}"',
    f'10.0.0.77 - - [{now_nginx}] "GET /%2e%67%69%74/%63%6f%6e%66%69%67 HTTP/1.1" 403 150 "-" "{CHROME_UA}"'
    # /.git/config en HEX
]

# 🧪 ESCENARIO 3: Falso Positivo Complejo (Tráfico Técnico Benigno)
# Un usuario administrador legítimo (192.168.1.50) está subiendo una entrada de blog o un ticket
# de soporte técnico que contiene fragmentos de código. No debe ser bloqueado por la IA.
FALSE_POSITIVE_LOGS = [
    f'192.168.1.50 - - [{now_nginx}] "POST /wp-admin/post.php?action=edit&text=Como%20prevenir%20un%20SELECT%20from%20users%20en%20SQL HTTP/1.1" 200 3200 "http://localhost/wp-admin/" "Mozilla/5.0"',
    f'192.168.1.50 - - [{now_nginx}] "GET /wp-admin/css/dashboard.css HTTP/1.1" 200 1400 "http://localhost/wp-admin/" "Mozilla/5.0"'
]


def print_banner():
    print("\n" + "=" * 80)
    print("  🔥 POCH DE EVASIÓN AVANZADA - PROBANDO LOS LÍMITES DE LA IA")
    print("  🕵️‍♂️ Evaluando User-Agent Spoofing, Ofuscación y Ataques Low & Slow")
    print("=" * 80 + "\n")


def print_section(title: str):
    print(f"\n{'─' * 80}")
    print(f"  {title}")
    print(f"{'─' * 80}\n")


def analyze_threat_assessment(assessment: dict) -> None:
    threat_level = assessment.get("threat_level", "UNKNOWN")
    threat_score = assessment.get("threat_score", 0)
    threat_detected = assessment.get("threat_detected", False)
    indicators = assessment.get("indicators_found", [])
    reasoning = assessment.get("reasoning_summary", "")
    recommendation = assessment.get("recommendation", "")
    kill_chain = assessment.get("kill_chain_phase", None)

    level_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NONE": "⚪"
    }.get(threat_level, "❓")

    print(f"{level_emoji} VEREDICTO DE AMENAZA")
    print(f"├─ Amenaza Detectada: {'✅ SÍ' if threat_detected else '❌ NO'}")
    print(f"├─ Nivel de Severidad: {threat_level} (Puntuación: {threat_score}/100)")
    if kill_chain:
        print(f"├─ Fase del Cyber Kill Chain: {kill_chain}")
    print(f"└─ Total de Indicadores Identificados: {len(indicators)}\n")

    if indicators:
        print("📍 INDICADORES DETECTADOS POR LA IA:")
        for i, indicator in enumerate(indicators, 1):
            print(f"  {i}. {indicator}")
        print()

    if reasoning:
        print("💭 RAZONAMIENTO DEL AGENTE IA:")
        print(f"  {reasoning}\n")

    if recommendation:
        print("⚡ RECOMENDACIÓN DE MITIGACIÓN:")
        for line in recommendation.split('\n'):
            if line.strip():
                print(f"  {line}")
        print()


async def run_evasion_poc():
    print_banner()
    print(f"[ℹ️] Sincronizando logs con timestamps reales UTC: {now_nginx}\n")

    async with httpx.AsyncClient(timeout=180.0) as client:
        try:
            # 1. Inyectar Escenario 1 (Low & Slow)
            print_section("PASO 1: INYECTANDO ATAQUE 'LOW & SLOW' (IP: 10.0.0.99)")
            print("Enviando tráfico mezclado con firmas ocultas bajo un UA legítimo...")
            res1 = await client.post(f"{BASE_URL}/ingest/raw", json=LOW_AND_SLOW_LOGS)
            print(f"-> Estado: {res1.json()['status']}\n")

            # 2. Inyectar Escenario 2 (Ofuscación)
            print_section("PASO 2: INYECTANDO PAYLOADS OFUSCADOS EN HEX/URL (IP: 10.0.0.77)")
            print("Enviando ataques codificados con caracteres especiales (%2e%2e%2f)...")
            res2 = await client.post(f"{BASE_URL}/ingest/raw", json=OFUSCATED_ATTACK_LOGS)
            print(f"-> Estado: {res2.json()['status']}\n")

            # 3. Inyectar Escenario 3 (Falso Positivo)
            print_section("PASO 3: INYECTANDO FALSO POSITIVO COMPLEJO (IP: 192.168.1.50)")
            print("Simulando administrador escribiendo un artículo técnico sobre SQLi...")
            res3 = await client.post(f"{BASE_URL}/ingest/raw", json=FALSE_POSITIVE_LOGS)
            print(f"-> Estado: {res3.json()['status']}\n")

            # 4. Espera de la ventana temporal
            print_section("PASO 4: CRONÓMETRO DE VENTANA")
            print("Esperando 61 segundos para procesar el lote completo de manera asíncrona...")
            for i in range(61, 0, -1):
                sys.stdout.write(f"\r⏳ Liberando ventana en: {i:2d}s ")
                sys.stdout.flush()
                await asyncio.sleep(1)
            print("\n\n✅ Ventana cerrada. Orquestando evaluación en el LLM...\n")

            # 5. Forzar Flush y Análisis Ejecutivo
            flush_response = await client.post(f"{BASE_URL}/flush", timeout=180.0)
            result = flush_response.json()

            # Resumen General
            print_section("📊 RESUMEN GENERAL DE DEFENSAS (Métricas de la IA)")
            threat_summary = result.get("threat_summary", {})
            print(f"Estado de la Infraestructura: {threat_summary.get('overall_threat_status', '❓')}")
            print(f"├─ 🔴 Amenazas Críticas: {threat_summary.get('critical_threats', 0)}")
            print(f"├─ 🟠 Amenazas Altas: {threat_summary.get('high_threats', 0)}")
            print(f"├─ 🟡 Amenazas Medias: {threat_summary.get('medium_threats', 0)}")
            print(f"├─ 🟢 Amenazas Bajas: {threat_summary.get('low_threats', 0)}")
            print(f"├─ ⚪ Tráfico Limpio / Falsos Positivos Evitados: {threat_summary.get('clean', 0)}")
            print(f"└─ Total Indicadores Extraídos: {threat_summary.get('total_unique_indicators', 0)}\n")

            # Inspección detallada de Evasiones
            print_section("🔍 VEREDICTO DE LA IA CONTRA TÉCNICAS DE EVASIÓN")

            details = result.get("details", [])
            for detail in details:
                source_ip = detail.get("source_ip", "UNKNOWN")
                window_info = detail.get("window_info", {})
                threat_assessment = detail.get("threat_assessment", {})

                print(f"📡 Evaluación para origen IP: {source_ip}")
                print(f"   [Peticiones totales en ventana: {window_info.get('total_requests', 0)}]")
                print(f"   [Tasa de peticiones: {window_info.get('requests_per_second', 0):.2f} req/s]")
                print("-" * 50)

                analyze_threat_assessment(threat_assessment)
                print("=" * 60 + "\n")

            print_section("✨ FIN DE LA EVALUACIÓN DE EVASIÓN")
            print("Revisa si el modelo Gemini fue capaz de:")
            print(" 1. Detectar a 10.0.0.99 ignorando que su User-Agent decía 'Chrome'.")
            print(" 2. Decodificar el Path Traversal Hex/URL de 10.0.0.77.")
            print(" 3. Marcar como CLEAN (Limpio) al administrador técnico 192.168.1.50.")
            print("\n" + "=" * 80 + "\n")

        except httpx.ConnectError:
            print("\n❌ ERROR: El Core Orchestrator no está respondiendo en el puerto 8000.")
            sys.exit(1)
        except Exception as exc:
            print(f"\n❌ ERROR inesperado: {str(exc)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_evasion_poc())