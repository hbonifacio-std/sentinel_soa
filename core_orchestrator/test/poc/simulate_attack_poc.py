"""
Script de Simulación de Ataque para la Prueba de Concepto (PoC).

Genera dinámicamente timestamps basados en el tiempo real actual para sincronizar
perfectamente la ventana temporal del Core Orchestrator con el reloj de Docker.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
import asyncio
import httpx
import json
from datetime import datetime, timezone

BASE_URL = "http://localhost:8000/api/v1/telemetry"

# Obtenemos la hora actual del sistema en formato Nginx estándar [day/Month/year:hour:minute:second +0000]
now_nginx = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")

# Payloads dinámicos con la hora exacta del sistema en ejecución
BENIGN_LOGS = [
    f'192.168.1.100 - - [{now_nginx}] "GET /index.html HTTP/1.1" 200 4500 "-" "Mozilla/5.0"',
    f'192.168.1.100 - - [{now_nginx}] "GET /assets/style.css HTTP/1.1" 200 1200 "-" "Mozilla/5.0"',
    f'192.168.1.102 - - [{now_nginx}] "GET /favicon.ico HTTP/1.1" 200 350 "-" "Mozilla/5.0"'
]

ATTACK_LOGS = [
    f'10.0.0.66 - - [{now_nginx}] "GET /etc/passwd HTTP/1.1" 404 230 "-" "Nikto-Scanner"',
    f'10.0.0.66 - - [{now_nginx}] "GET /../../win.ini HTTP/1.1" 404 230 "-" "Nikto-Scanner"',
    f'10.0.0.66 - - [{now_nginx}] "GET /admin/login.php?id=1%27%20OR%201=1 HTTP/1.1" 500 520 "-" "Nikto-Scanner"',
    f'10.0.0.66 - - [{now_nginx}] "GET /wp-config.bak HTTP/1.1" 404 230 "-" "Nikto-Scanner"',
    f'10.0.0.66 - - [{now_nginx}] "GET /.git/config HTTP/1.1" 403 150 "-" "Nikto-Scanner"'
]


async def run_poc_scenario():
    """
    Ejecuta la secuencia de inyección de la PoC y despliega los resultados de la IA.
    """
    print("=== INICIANDO SIMULACIÓN DE ESCENARIO CONTROLADO (PoC) ===")
    print(f"[i] Sincronizando timestamps de telemetría a la hora actual UTC: {now_nginx}")
    
    async with httpx.AsyncClient() as client:
        try:
            # 1. Enviar Tráfico Benigno
            print("\n[+] Inyectando tráfico web legítimo (Líneas base)...")
            response = await client.post(f"{BASE_URL}/ingest/raw", json=BENIGN_LOGS)
            print(f"Respuesta Ingesta: {response.status_code} | {response.json()}")

            # 2. Enviar Ráfaga de Ataque (IP: 10.0.0.66)
            print("\n[+] Inyectando ráfaga de escaneo sospechoso (Fase de Reconocimiento)...")
            response_atk = await client.post(f"{BASE_URL}/ingest/raw", json=ATTACK_LOGS)
            print(f"Respuesta Ingesta: {response_atk.status_code} | {response_atk.json()}")

            # ====================================================================
            # ⏳ CONTROL TEMPORAL METODOLÓGICO PARA TESIS
            # ====================================================================
            print("\n[⏳] Esperando 61 segundos para que la ventana expire en el Core de forma natural...")
            for i in range(61, 0, -1):
                sys.stdout.write(f"\rTiempo restante: {i} segundos... ")
                sys.stdout.flush()
                await asyncio.sleep(1)
            print("\n[✔] Tiempo cumplido. La ventana analítica ha expirado.")
            # ====================================================================

            # 3. Forzar el Flush de la ventana temporal de forma síncrona para auditar el veredicto
            print("\n[+] Forzando cierre de ventana y ejecución del ciclo analítico MCP...")
            flush_response = await client.post(f"{BASE_URL}/flush", timeout=180.0)
            
            print("\n=======================================================")
            print("=== VEREDICTO GENERADO POR EL AGENTE DE ORQUESTACIÓN ===")
            print("=======================================================")
            
            print(json.dumps(flush_response.json(), indent=2, ensure_ascii=False))
            
            print("\n[🎉] ¡Simulación de la PoC concluida de forma exitosa!")

        except httpx.ConnectError:
            print("\n[❌] Error: No se pudo conectar al Core Orchestrator. Asegúrate de levantar FastAPI primero (uvicorn).")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[❌] Falla en la ejecución del script PoC: {str(exc)}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_poc_scenario())