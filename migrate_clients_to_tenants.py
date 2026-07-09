#!/usr/bin/env python
"""
Migration script: Move authorized_telemetry_clients to unified tenants collection.

This script migrates existing telemetry clients from the old
'authorized_telemetry_clients' collection to the new unified 'tenants'
collection while preserving all fields and relationships.
"""

import asyncio
import logging
import hashlib
import os
from pymongo import AsyncMongoClient
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def migrate_telemetry_clients_to_tenants():
    """Migrate authorized_telemetry_clients to tenants collection."""
    
    mongo_host = os.getenv("MONGO_HOST", "localhost")
    mongo_port = os.getenv("MONGO_PORT", "27017")
    mongo_user = os.getenv("MONGO_USER", "sentinel_user")
    mongo_password = os.getenv("MONGO_PASSWORD", "sentinel_password")
    
    uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/auth?authSource=admin"
    
    print("\n" + "="*70)
    print("🔄 TELEMETRY CLIENTS → TENANTS MIGRATION")
    print("="*70)
    
    try:
        client = AsyncMongoClient(uri)
        db = client['auth']
        
        # Collections
        old_collection = db['authorized_telemetry_clients']
        new_collection = db['tenants']
        
        # Get all telemetry clients
        clients = await old_collection.find({}).to_list(length=None)
        logger.info(f"Found {len(clients)} telemetry clients to migrate")
        
        if len(clients) == 0:
            logger.info("No clients to migrate")
            await client.close()
            return
        
        migrated_count = 0
        skipped_count = 0
        
        for old_client in clients:
            client_id = old_client.get('client_id')
            logger.info(f"\nProcessing client: {client_id}")
            
            # Check if already exists in tenants (by client_id)
            existing = await new_collection.find_one({"client_id": client_id})
            if existing:
                logger.warning(f"  ⚠️  Client {client_id} already exists in tenants collection. Skipping.")
                skipped_count += 1
                continue
            
            # Generate tenant_id from client_id
            tenant_id = f"client-{client_id}"
            
            # Generate tenant API key hash (different from telemetry api_key)
            import secrets
            tenant_api_key_plaintext = f"sk_{secrets.token_urlsafe(32)}"
            tenant_api_key_hash = hashlib.sha256(tenant_api_key_plaintext.encode()).hexdigest()
            
            # Build tenant document preserving telemetry client fields
            tenant_doc = {
                "tenant_id": tenant_id,
                "display_name": old_client.get('display_name', client_id),
                "rate_limit_per_minute": 60,  # Default
                "is_active": old_client.get('is_active', True),
                
                # Telemetry client fields (preserved from old collection)
                "client_id": old_client.get('client_id'),
                "source_id": old_client.get('source_id'),
                "description": old_client.get('description'),
                "api_key": old_client.get('api_key'),
                "hmac_public_key": old_client.get('hmac_public_key'),
                "hmac_secret": old_client.get('hmac_secret'),
                
                # Tenant API key (for tenant auth)
                "api_key_hash": tenant_api_key_hash,
                "api_key_plaintext": None,  # Only shown at creation
                
                # Timestamps
                "created_at": old_client.get('created_at', datetime.now(timezone.utc)),
                "updated_at": old_client.get('updated_at', datetime.now(timezone.utc)),
            }
            
            # Insert into tenants collection
            result = await new_collection.insert_one(tenant_doc)
            logger.info(f"  ✅ Migrated to tenant: {tenant_id}")
            logger.info(f"     Tenant API Key Hash: {tenant_api_key_hash[:16]}...")
            migrated_count += 1
        
        # Summary
        print("\n" + "="*70)
        print(f"✅ MIGRATION COMPLETE")
        print("="*70)
        print(f"  Migrated: {migrated_count}")
        print(f"  Skipped:  {skipped_count}")
        print(f"  Total:    {len(clients)}")
        print("\n📌 Next Steps:")
        print("  1. Verify tenants collection has all migrated clients")
        print("  2. Update security dependencies to use TenantService")
        print("  3. Test telemetry ingestion with new unified auth")
        print("  4. Archive old 'authorized_telemetry_clients' collection")
        
        await client.close()
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}", exc_info=True)
        print("\n" + "="*70)
        print(f"❌ MIGRATION FAILED: {e}")
        print("="*70)


if __name__ == "__main__":
    asyncio.run(migrate_telemetry_clients_to_tenants())
