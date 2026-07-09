"""Count documents missing tenant_id in common collections.
Usage: python scripts\count_missing_tenant.py <TENANT_ID>
"""
import sys
import asyncio
from core_orchestrator.infrastructure.config.database import DatabaseManager

async def main(tenant_id: str | None):
    dbm = DatabaseManager()
    dbm.connect()
    try:
        sentinel_db = dbm.get_sentinel_db()
        collections = ["raw_telemetry", "analysis_reports", "heuristic_rules"]
        for c in collections:
            coll = sentinel_db[c]
            # motor-style async count
            try:
                cnt = await coll.count_documents({"tenant_id": {"$exists": False}})
            except TypeError:
                # fallback for sync pymongo
                cnt = coll.count_documents({"tenant_id": {"$exists": False}})
            print(f"{c}: {cnt} documents missing tenant_id")
    finally:
        dbm.disconnect()

if __name__ == '__main__':
    tid = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(main(tid))
