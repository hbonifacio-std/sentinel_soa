"""
Test unitario para validar el motor de heurísticas de amenazas.
"""
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import sys
import os
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), "../../../")))


# Crear una ventana de ataque típico
window_id = uuid4()
now = datetime.now(timezone.utc)

attack_window = WebActivityWindowInput(
    window_id=window_id,
    source_ip="10.0.0.66",
    window_start_utc=now,
    window_end_utc=now + timedelta(seconds=60),
    total_requests=9,
    unique_uris_requested=[
        "/etc/passwd",
        "/admin",
        "/.git/config",
        "/wp-login.php",
        "/.env",
    ],
    http_methods_distribution={"GET": 9},
    response_codes_distribution={"404": 8, "403": 1},
    user_agents_observed=["Nikto-Scanner/2.1"],
    requests_per_second_avg=0.15
)

print("=" * 60)
print("TEST DE MOTOR DE HEURÍSTICAS - ATAQUE NIKTO")
print("=" * 60)
print(f"IP: {attack_window.source_ip}")
print(f"URIs solicitadas: {attack_window.unique_uris_requested}")
print(f"User-Agents: {attack_window.user_agents_observed}")
print(
    f"Ratio 404: {attack_window.response_codes_distribution.get('404', 0)}/{attack_window.total_requests}")
print()

# Ejecutar análisis heurístico
threat_score, indicators, reasoning = ThreatHeuristics.analyze(attack_window)

print(f"THREAT SCORE: {threat_score}/100")
print(f"INDICADORES DETECTADOS ({len(indicators)}):")
for i, ind in enumerate(indicators, 1):
    print(f"  {i}. {ind}")
print()
print(f"REASONING: {reasoning}")
print()

print("=" * 60)
if threat_score >= 70:
    print("✓ RESULTADO: AMENAZA DETECTADA (Score alto)")
    print("  Estado esperado: threat_detected=TRUE, threat_level=HIGH")
elif threat_score >= 40:
    print("⚠ RESULTADO: Amenaza moderada")
    print("  Estado esperado: threat_detected puede ser TRUE, threat_level=MEDIUM")
else:
    print("✗ RESULTADO: SIN AMENAZA DETECTADA (Score bajo - FALLA!)")
    print("  Estado esperado: threat_detected=FALSE")

print("=" * 60)
print()

# Test 2: Tráfico benigno
print("=" * 60)
print("TEST 2: TRÁFICO BENIGNO")
print("=" * 60)

benign_window = WebActivityWindowInput(
    window_id=uuid4(),
    source_ip="192.168.1.100",
    window_start_utc=now,
    window_end_utc=now + timedelta(seconds=60),
    total_requests=3,
    unique_uris_requested=[
        "/index.html",
        "/assets/style.css",
        "/favicon.ico",
    ],
    http_methods_distribution={"GET": 3},
    response_codes_distribution={"200": 3},
    user_agents_observed=["Mozilla/5.0"],
    requests_per_second_avg=0.05
)

benign_score, benign_indicators, benign_reasoning = ThreatHeuristics.analyze(
    benign_window)

print(f"THREAT SCORE: {benign_score}/100")
print(f"INDICADORES: {len(benign_indicators)}")
print(f"REASONING: {benign_reasoning}")
print()

if benign_score < 20:
    print("✓ RESULTADO: Tráfico benigno correctamente clasificado")
else:
    print(
        f"⚠ RESULTADO: Score inesperado ({benign_score}) para tráfico benigno")

print("=" * 60)
