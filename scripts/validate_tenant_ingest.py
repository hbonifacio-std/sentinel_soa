"""Validation script to test tenant-aware ingest with ENFORCE_TENANT_AUTH=true."""
import os
import asyncio
import httpx
from datetime import datetime

async def validate_ingest():
    api_url = os.getenv("API_URL", "http://localhost:8000")
    tenant_api_key = os.getenv("TENANT_API_KEY")
    
    if not tenant_api_key:
        print("ERROR: TENANT_API_KEY not set. Exiting.")
        return
    
    client_id = "victim-app-01"
    client_api_key = "sentinel_sk_live_v1_KLPLxqIZWPaelBI66EUVQKv6xHAMFqP9n"
    
    payload = [
        {
            "source_id": "victim-app-01",
            "source_ip": "192.168.1.100",
            "timestamp_utc": datetime.utcnow().isoformat(),
            "http": {
                "method": "GET",
                "path": "/test",
                "status_code": 200
            }
        }
    ]
    
    base_headers = {
        "X-Sentinel-Client-ID": client_id,
        "X-Sentinel-API-Key": client_api_key
    }
    
    # Test 1: WITHOUT tenant key (should fail 401)
    print("\n=== Test 1: WITHOUT X-Api-Key (should fail 401) ===")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{api_url}/api/v1/telemetry/ingest/batch",
            json=payload,
            headers=base_headers,
            timeout=10.0
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 401:
            print("PASS: Rejected without X-Api-Key")
        else:
            print(f"FAIL: Expected 401, got {resp.status_code}")
            print(f"Response: {resp.text[:300]}")
    
    # Test 2: WITH valid tenant key (should succeed 202)
    print("\n=== Test 2: WITH valid X-Api-Key ===")
    headers_with_tenant = {**base_headers, "X-Api-Key": tenant_api_key}
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{api_url}/api/v1/telemetry/ingest/batch",
            json=payload,
            headers=headers_with_tenant,
            timeout=10.0
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code in (200, 202):
            print("PASS: Accepted with valid X-Api-Key")
        else:
            print(f"FAIL: Expected 200/202, got {resp.status_code}")
            print(f"Response: {resp.text[:300]}")
    
    # Test 3: WITH invalid tenant key (should fail 401)
    print("\n=== Test 3: WITH invalid X-Api-Key ===")
    headers_invalid = {**base_headers, "X-Api-Key": "sk_invalid_key_12345"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{api_url}/api/v1/telemetry/ingest/batch",
            json=payload,
            headers=headers_invalid,
            timeout=10.0
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 401:
            print("PASS: Rejected invalid X-Api-Key")
        else:
            print(f"FAIL: Expected 401, got {resp.status_code}")
            print(f"Response: {resp.text[:300]}")

if __name__ == "__main__":
    asyncio.run(validate_ingest())
