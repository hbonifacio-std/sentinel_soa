#!/usr/bin/env python3
"""
Bootstrap local seed data for Sentinel SOA.

Creates the initial web user, ensures heuristic rules exist in `heuristy`,
and seeds authorized telemetry clients that are cached in Redis.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional, cast, Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_orchestrator.domain.models.auth.user import UserCreate
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientCreate, TelemetryBootstrapSummary

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.persistence.mongo_user_repository import MongoUserRepository
from core_orchestrator.application.modules.auth_clients.services.user_service import UserService
from core_orchestrator.infrastructure.persistence.mongo_telemetry_client_repository import \
    MongoTelemetryClientRepository
from core_orchestrator.infrastructure.persistence.caching_telemetry_client_repository import CachingTelemetryClientRepository
from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.infrastructure.cache.redis_cache import RedisCache
from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import RedisRulesBundleCache
from core_orchestrator.infrastructure.security.signature_verifier import HmacSignatureVerifier
from core_orchestrator.infrastructure.security.password_hasher import BcryptPasswordHasher
from core_orchestrator.application.modules.analysis_reports.services.default_rule_validator_service import DefaultRuleValidatorService

logger = logging.getLogger("bootstrap_local_data")
DEFAULT_RULES_SEED = ROOT / "data" / "mongodb" / "heuristic_rules.json"
DEFAULT_USERS_SEED = ROOT / "data" / "users_seed.json"
DEFAULT_TELEMETRY_CLIENTS_SEED = ROOT / "data" / "telemetry_clients_seed.json"


def _load_seed(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


async def create_forensic_reader_user(db_manager: DatabaseManager) -> None:
    """Ensures the forensic_reader user exists with read-only permissions on the telemetry DB."""
    admin_db = db_manager.mongo_client.get_database("admin")
    forensic_user = "forensic_reader"
    # Using a fixed password for local bootstrap. In production, this would be an env var.
    forensic_password = "supersecretforensicpassword" 

    try:
        # Check if user already exists (this method might vary based on pymongo version)
        # A more robust check might query system.users collection
        user_info = await admin_db.command("usersInfo", forensic_user)
        if user_info and user_info.get("users"):
            logger.info("MongoDB user '%s' already exists.", forensic_user)
            return
        
        await admin_db.command({
            "createUser": forensic_user,
            "pwd": forensic_password,
            "roles": [{ "role": "read", "db": "telemetry" }]
        })
        logger.info("MongoDB user '%s' created successfully with read-only access to 'telemetry' DB.", forensic_user)
    except Exception as e:
        logger.error("Failed to create MongoDB user '%s': %s", forensic_user, e)
        # If user already exists, a command error might be raised, handle it.
        if "already exists" in str(e):
            logger.info("MongoDB user '%s' creation skipped as it already exists.", forensic_user)
        else:
            raise


async def seed_users(user_service: UserService, seed_path: Path, overwrite_existing: bool) -> TelemetryBootstrapSummary:
    summary = TelemetryBootstrapSummary()
    users_data = _load_seed(seed_path)

    for user_data in users_data:
        user_create = UserCreate(**user_data)
        # Verificar si el usuario ya existe con un método real de UserService
        existing_user = await user_service.get_user_by_username(user_create.username)

        if not existing_user:
            # Si no existe, se crea usando el método real
            user = await user_service.create_user(user_create)
            summary.users_created += 1
            logger.info("Bootstrap user ready: %s (role=%s)", user.username, user.role)
        else:
            if overwrite_existing:
                summary.users_updated += 1
                logger.info("Bootstrap user already exists (skipped update): %s", existing_user.username)
            else:
                summary.users_skipped += 1
                logger.info("Bootstrap user skipped (already exists): %s", existing_user.username)

    return summary


async def seed_telemetry_clients(telemetry_client_service: TelemetryClientService, seed_path: Path,
                                 overwrite_existing: bool) -> TelemetryBootstrapSummary:
    summary = TelemetryBootstrapSummary()
    clients_data = _load_seed(seed_path)
    for client_data in clients_data:
        client, created, updated = await telemetry_client_service.upsert_client(
            TelemetryClientCreate(**client_data),
            overwrite_existing=overwrite_existing,
        )
        if created:
            summary.clients_created += 1
        elif updated:
            summary.clients_updated += 1
        else:
            summary.clients_skipped += 1
        logger.info("Bootstrap telemetry client ready: %s", client.client_id)
    return summary


async def bootstrap(
        users_seed: Path,
        clients_seed: Path,
        overwrite_existing: bool,
        force_rules: bool,
) -> TelemetryBootstrapSummary:
    db_manager = DatabaseManager()
    db_manager.connect()

    await create_forensic_reader_user(db_manager)

    result: Optional[TelemetryBootstrapSummary] = None

    try:
        if db_manager.redis_client is None:
            raise RuntimeError("Redis client is not connected")

        user_repo = MongoUserRepository(db_manager)
        password_hasher = BcryptPasswordHasher()
        user_service = UserService(user_repository=user_repo, password_hasher=password_hasher)

        redis_cache = RedisCache(redis_client=db_manager.redis_client)

        mongo_telemetry_client_repo = MongoTelemetryClientRepository(db_manager)
        telemetry_client_repo = CachingTelemetryClientRepository(
            primary_repository=mongo_telemetry_client_repo,
            cache=redis_cache,
        )
        signature_verifier = HmacSignatureVerifier()
        telemetry_client_service = TelemetryClientService(
            telemetry_client_repository=telemetry_client_repo,
            signature_verifier=signature_verifier,
        )

        rule_repo = MongoRuleRepository(db_manager)
        audit_repo = MongoAuditRepository(db_manager)
        rule_service = RuleService(
            rule_repository=rule_repo,
            audit_repository=audit_repo,
            rules_bundle_cache=RedisRulesBundleCache(redis_client=db_manager.redis_client),
            rule_validator=DefaultRuleValidatorService(),
        )

        # Corregido: Llamar a los índices a través de los repositorios
        await user_repo.ensure_indexes()
        await mongo_telemetry_client_repo.ensure_indexes()

        users_summary = await seed_users(user_service, users_seed, overwrite_existing)
        clients_summary = await seed_telemetry_clients(telemetry_client_service, clients_seed, overwrite_existing)

        rules_db = db_manager.get_rules_db()
        rules_collection = rules_db["heuristic_rules"]
        existing_rules = await rules_collection.count_documents({})

        if force_rules:
            await rules_db["heuristic_rules"].delete_many({})
            await rules_db["rule_versions"].delete_many({})
            await rules_db["rule_audit_log"].delete_many({})
            if db_manager.redis_client:
                await rule_service.invalidate_rules_cache()
            existing_rules = 0
            logger.info("Existing heuristic rules cleared before reseed.")

        rules_engine = RulesEngineService(rules_service=rule_service)
        await rules_engine.initialize()
        total_rules = await rules_collection.count_documents({})

        result = TelemetryBootstrapSummary(
            users_created=users_summary.users_created,
            users_skipped=users_summary.users_skipped,
            users_updated=users_summary.users_updated,
            clients_created=clients_summary.clients_created,
            clients_skipped=clients_summary.clients_skipped,
            clients_updated=clients_summary.clients_updated,
            rules_seeded=existing_rules == 0 and total_rules > 0,
            cache_warmed_clients=0,
        )

        logger.info("Bootstrap completed successfully.")
    finally:
        if db_manager.mongo_client:
            await db_manager.mongo_client.close()

    if result is None:
        raise RuntimeError("Bootstrap finished without producing a summary")

    return cast(TelemetryBootstrapSummary, result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap local seed data for Sentinel SOA")
    parser.add_argument("--users-seed", type=Path, default=DEFAULT_USERS_SEED, help="Path to users seed JSON")
    parser.add_argument(
        "--clients-seed",
        type=Path,
        default=DEFAULT_TELEMETRY_CLIENTS_SEED,
        help="Path to telemetry clients seed JSON",
    )
    parser.add_argument(
        "--overwrite-existing",
        action="store_true",
        help="Update existing seeded users/clients instead of leaving them untouched",
    )
    parser.add_argument(
        "--force-rules",
        action="store_true",
        help="Clear rule collections and recreate heuristic rules from the canonical seed",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    for seed_path in (args.users_seed, args.clients_seed, DEFAULT_RULES_SEED):
        if not seed_path.exists():
            logger.error("Seed file not found: %s", seed_path)
            sys.exit(1)

    summary = asyncio.run(
        bootstrap(
            users_seed=args.users_seed,
            clients_seed=args.clients_seed,
            overwrite_existing=args.overwrite_existing,
            force_rules=args.force_rules,
        )
    )
    print(json.dumps(summary.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()