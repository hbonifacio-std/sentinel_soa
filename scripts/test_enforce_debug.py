"""Debug script to test ENFORCE_TENANT_AUTH behavior."""
import os
import asyncio
import httpx
from datetime import datetime

async def test():
    api_url = os.getenv("API_URL", "http://localhost:8000")
    
    client_id = "victim-app-01"
    client_api_key = "sentinel_sk_live_v1_KLPLxqIZWPaelBI66EUVQKv6xHAMFqP9n"
    
    payload = [{
        "source_id": "victim-app-01",
        "source_ip": "192.168.1.100",
        "timestamp_utc": datetime.utcnow().isoformat(),
        "http": {
            "method": "GET",
            "path": "/test",
            "status_code": 200
        }
    }]
    
    base_headers = {
        "X-Sentinel-Client-ID": client_id,
        "X-Sentinel-API-Key": client_api_key
    }
    
    # Test WITHOUT X-Api-Key
    print("Test 1: Without X-Api-Key")
    async with httpx.AsyncClient() as c:
        resp = await c.post(
            f"{api_url}/api/v1/telemetry/ingest/batch",
            json=payload,
            headers=base_headers,
            timeout=10.0
        )
        print(f"  Status: {resp.status_code}")
        print(f"  Response: {resp.text[:200]}")

if __name__ == "__main__":
    asyncio.run(test())
