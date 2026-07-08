"""Utility script to create a tenant and optionally backfill existing telemetry/rules documents.

Usage:
  - Set environment variables: TENANT_ID and TENANT_API_KEY
  - Optionally set BACKFILL_COLLECTIONS to a comma-separated list (raw_telemetry,analysis_reports,heuristic_rules)

This script connects using core_orchestrator.infrastructure.config.database.DatabaseManager and performs safe operations.
"""
import os
import sys
import hashlib
import asyncio
from core_orchestrator.infrastructure.config.database import DatabaseManager


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def main():
    tenant_id = os.getenv("TENANT_ID")
    tenant_api_key = os.getenv("TENANT_API_KEY")
    backfill = os.getenv("BACKFILL_COLLECTIONS", "")

    if not tenant_id or not tenant_api_key:
        print("TENANT_ID and TENANT_API_KEY must be set. Aborting.")
        sys.exit(1)

    dbm = DatabaseManager()
    dbm.connect()
    try:
        sentinel_db = dbm.get_sentinel_db()
        tenants = sentinel_db.tenants

        api_key_hash = hash_key(tenant_api_key)
        existing = await tenants.find_one({"tenant_id": tenant_id})
        if existing:
            print(f"Tenant '{tenant_id}' already exists. Skipping creation.")
        else:
            await tenants.insert_one({
                "tenant_id": tenant_id,
                "display_name": tenant_id,
                "api_key_hash": api_key_hash,
                "rate_limit_per_minute": int(os.getenv("TENANT_RATE", 60)),
                "is_active": True,
            })
            print(f"Created tenant '{tenant_id}'.")

        if backfill:
            collections = [c.strip() for c in backfill.split(",") if c.strip()]
            for coll_name in collections:
                coll = sentinel_db[coll_name]
                res = await coll.update_many({"tenant_id": {"$exists": False}}, {"$set": {"tenant_id": tenant_id}})
                print(f"Backfilled {res.modified_count} documents in '{coll_name}' with tenant_id '{tenant_id}'.")

    finally:
        dbm.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
