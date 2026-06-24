#!/usr/bin/env python3
"""
Migration script to initialize users in MongoDB from seed data.

Loads users from data/users_seed.json and inserts them into MongoDB collection.
Run this script during application startup or manually to seed initial users.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_orchestrator.services.database import db
from core_orchestrator.services.user_service import UserService
from core_orchestrator.models.user import UserCreate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("migrate_users_to_mongodb")


async def migrate_users():
    """
    Load users from seed file and insert into MongoDB.
    
    Skips users that already exist (checked by username).
    """
    try:
        # Load seed data
        seed_file = ROOT / "data" / "users_seed.json"
        
        if not seed_file.exists():
            logger.error(f"Seed file not found: {seed_file}")
            return False
        
        with open(seed_file, "r") as f:
            users_data = json.load(f)
        
        logger.info(f"Loaded {len(users_data)} users from seed file")
        
        # Connect to MongoDB
        await db.connect_to_mongo()
        
        # Process each user
        created_count = 0
        skipped_count = 0
        
        for user_data in users_data:
            username = user_data.get("username")
            
            # Check if user already exists
            existing_user = await UserService.get_user_by_username(username)
            if existing_user:
                logger.info(f"User '{username}' already exists, skipping")
                skipped_count += 1
                continue
            
            # Create user
            try:
                user_create = UserCreate(
                    username=user_data.get("username"),
                    email=user_data.get("email"),
                    password=user_data.get("password"),
                    role=user_data.get("role", "viewer"),
                    is_active=user_data.get("is_active", True),
                )
                
                created_user = await UserService.create_user(user_create)
                logger.info(f"Created user: {created_user.username} (role: {created_user.role})")
                created_count += 1
            
            except Exception as e:
                logger.error(f"Error creating user '{username}': {e}")
        
        # Create unique index on username
        collection = await UserService.get_user_collection()
        try:
            await collection.create_index("username", unique=True)
            logger.info("Created unique index on username field")
        except Exception as e:
            logger.warning(f"Index creation or update: {e}")
        
        logger.info(f"Migration completed: {created_count} created, {skipped_count} skipped")
        
        # Disconnect from MongoDB
        await db.close_mongo_connection()
        
        return True
    
    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    success = asyncio.run(migrate_users())
    sys.exit(0 if success else 1)

