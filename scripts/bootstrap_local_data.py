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

# Provide safe defaults for local bootstrap so importing application modules
# doesn't fail when running in development without full env config.
import os
os.environ.setdefault("JWT_SECRET_KEY", "dev_jwt_secret_for_local_bootstrap")
# MCP settings used by some adapters; provide safe defaults for local runs
os.environ.setdefault("MCP_SERVER_URL", "http://localhost:8001")
os.environ.setdefault("MCP_INTERNAL_TOKEN", "dev-internal-token")


from core_orchestrator.infrastructure.dto.auth.auth_dto import UserCreateDTO
from core_orchestrator.domain.entities.auth.telemetry_client import TelemetryBootstrapSummary

from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.infrastructure.adapters.mongodb.mongo_user_repository_adapter import MongoUserRepositoryAdapter
from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.infrastructure.adapters.mongodb.mongo_tenant_repository_adapter import \
    MongoTenantRepositoryAdapter as MongoTelemetryClientRepository
from core_orchestrator.infrastructure.adapters.redis.redis_telemetry_tenant_adapter import RedisTelemetryTenantRepositoryAdapter
from core_orchestrator.infrastructure.adapters.redis.base_redis_adapter import RedisBaseCacheAdapter
from core_orchestrator.application.modules.rules_heuristics.rules_engine_service import RulesEngineService
from core_orchestrator.infrastructure.adapters.mongodb.mongo_rule_repository import MongoAuditRulesAdapter
from core_orchestrator.application.modules.rules_heuristics.rule_service import RuleService
from core_orchestrator.infrastructure.adapters.redis.redis_rules_bundle_adapter import RedisRulesBundleAdapter
# signature_verifier may be missing in refactor; provide a local shim for bootstrap when absent

from core_orchestrator.infrastructure.adapters.helper.default_rule_validator_adapter import DefaultRuleValidatorAdapter

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


async def seed_users(user_service: UserService, user_repo: MongoUserRepositoryAdapter, seed_path: Path, overwrite_existing: bool) -> TelemetryBootstrapSummary:
    """Seed users; if overwrite_existing is True, update existing users' hashed_password using the provided seed password.

    This addresses cases where previous runs stored plaintext in the 'hashed_password' field by re-hashing the known seed password.
    """
    from datetime import datetime, timezone

    summary = TelemetryBootstrapSummary()
    users_data = _load_seed(seed_path)

    for user_data in users_data:
        # Build DTO for creation (separate client_id in seed)
        user_create = UserCreateDTO(
            username=user_data["username"],
            email=user_data["email"],
            password=user_data["password"],
            role=user_data.get("role", "user"),
        )
        client_id = user_data.get("client_id") or user_create.username

        # Check repository directly for existence
        existing_user = await user_repo.get_by_username(user_create.username)

        if not existing_user:
            user = await user_service.create_user(user_create, client_id)
            summary.users_created += 1
            logger.info("Bootstrap user ready: %s (role=%s)", user.username, user.role)
        else:
            if overwrite_existing:
                # Re-hash the seed password and update the stored hashed_password field.
                try:
                    # Prefer the service's password hasher if available
                    hasher = getattr(user_service, '_password_hasher', None)
                    if hasher is None:
                        raise AttributeError
                    new_hash = hasher.hash_password(user_data["password"])
                except Exception:
                    # Fallback: simple PBKDF2 in-script hasher
                    import hashlib, os
                    iterations = 200000
                    algo = 'sha256'
                    salt = os.urandom(16)
                    dk = hashlib.pbkdf2_hmac(algo, user_data["password"].encode('utf-8'), salt, iterations)
                    new_hash = f"pbkdf2_{algo}${iterations}${salt.hex()}${dk.hex()}"

                # Update DB record directly via repository's collection
                await user_repo.collection.find_one_and_update(
                    {"username": user_create.username},
                    {
                        "$set": {
                            "hashed_password": new_hash,
                            "updated_at": datetime.now(timezone.utc)
                        }
                    },
                    return_document=True,
                )

                summary.users_updated += 1
                logger.info("Bootstrap user updated (password re-hashed): %s", existing_user.username)
            else:
                summary.users_skipped += 1
                logger.info("Bootstrap user skipped (already exists): %s", existing_user.username)

    return summary


async def seed_telemetry_clients(tenant_repo: MongoTelemetryClientRepository, seed_path: Path, overwrite_existing: bool) -> TelemetryBootstrapSummary:
    """Seed tenants (authorized telemetry clients). Uses tenant_repo directly to create or update entries."""
    summary = TelemetryBootstrapSummary()
    clients_data = _load_seed(seed_path)
    import hashlib
    import secrets
    from core_orchestrator.domain.entities.auth.tenant import Tenant

    for client_data in clients_data:
        client_id = client_data["client_id"]
        existing = await tenant_repo.get_by_client_id(client_id, include_inactive=True)

        api_key_plaintext = client_data.get("api_key")
        if api_key_plaintext:
            api_key_hash = hashlib.sha256(api_key_plaintext.encode("utf-8")).hexdigest()
        else:
            # generate a key for local use, but avoid persisting plaintext
            api_key_plaintext = f"sk_{secrets.token_urlsafe(32)}"
            api_key_hash = hashlib.sha256(api_key_plaintext.encode("utf-8")).hexdigest()

        # Build tenant but DO NOT persist the plaintext API key in DB (pass None)
        tenant = Tenant(
            client_id=client_id,
            display_name=client_data.get("display_name", client_id),
            description=client_data.get("description"),
            rate_limit_per_minute=client_data.get("rate_limit_per_minute", 60),
            is_active=client_data.get("is_active", True),
            api_key_hash=api_key_hash,
            api_key_plaintext=None,
        )

        if existing:
            if overwrite_existing:
                # Update hash only; do not store plaintext
                await tenant_repo.update(client_id,
                                         display_name=tenant.display_name,
                                         description=tenant.description,
                                         rate_limit_per_minute=tenant.rate_limit_per_minute,
                                         is_active=tenant.is_active,
                                         api_key_hash=tenant.api_key_hash,
                                         api_key_plaintext=None)
                summary.clients_updated += 1
                logger.info("Bootstrap telemetry client updated (no plaintext stored): %s", client_id)
            else:
                summary.clients_skipped += 1
                logger.info("Bootstrap telemetry client skipped (already exists): %s", client_id)
        else:
            # create tenant storing only the hash, not the plaintext
            await tenant_repo.create(tenant, tenant.api_key_hash, None)
            summary.clients_created += 1
            logger.info("Bootstrap telemetry client created (no plaintext stored): %s", client_id)

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
        if db_manager.redis_client_window_telemetry is None:
            raise RuntimeError("Redis client is not connected")

        user_repo = MongoUserRepositoryAdapter(db_manager)
        # Use the project's canonical password hasher adapter so bootstrap creates hashes
        # identical to runtime (mirror function). This prevents storing incompatible hash formats.
        try:
            from core_orchestrator.infrastructure.adapters.security.password_hasher_adapter import PasswordHasherAdapter
            password_hasher = PasswordHasherAdapter()
        except Exception:
            # Fallback: if adapter is missing, keep PBKDF2 as last resort
            class PBKDF2PasswordHasher:
                def __init__(self, iterations: int = 200000):
                    import hashlib, os
                    self._iterations = iterations
                    self._algo = 'sha256'
                    self._salt_size = 16

                def hash_password(self, password: str) -> str:
                    import hashlib, os
                    salt = os.urandom(16)
                    dk = hashlib.pbkdf2_hmac(self._algo, password.encode('utf-8'), salt, self._iterations)
                    return f"pbkdf2_{self._algo}${self._iterations}${salt.hex()}${dk.hex()}"

                def verify_password(self, plain: str, hashed: str) -> bool:
                    import hashlib
                    try:
                        prefix, iterations_s, salt_hex, hash_hex = hashed.split('$')
                        iterations = int(iterations_s)
                        salt = bytes.fromhex(salt_hex)
                        dk = hashlib.pbkdf2_hmac(self._algo, plain.encode('utf-8'), salt, iterations)
                        return dk.hex() == hash_hex
                    except Exception:
                        return False

            password_hasher = PBKDF2PasswordHasher()

        # Instantiate service with the canonical hasher (mirror behavior)
        user_service = UserService(user_repository=user_repo, password_hasher=password_hasher)

        redis_cache = RedisBaseCacheAdapter(redis_client=db_manager.redis_client_window_telemetry)

        mongo_telemetry_client_repo = MongoTelemetryClientRepository(db_manager)
        telemetry_client_repo = RedisTelemetryTenantRepositoryAdapter(
            primary_repository=mongo_telemetry_client_repo,
            redis_client=redis_cache,
        )

        rule_repo = MongoAuditRulesAdapter(db_manager)
        audit_repo = MongoAuditRulesAdapter(db_manager)
        rule_service = RuleService(
            rule_repository=rule_repo,
            audit_repository=audit_repo,
            rules_bundle_cache=RedisRulesBundleAdapter(redis_client=db_manager.redis_client_window_telemetry),
            rule_validator=DefaultRuleValidatorAdapter(),
        )

        # Corregido: Llamar a los índices a través de los repositorios
        await user_repo.ensure_indexes()
        await mongo_telemetry_client_repo.ensure_indexes()

        users_summary = await seed_users(user_service, user_repo, users_seed, overwrite_existing)
        clients_summary = await seed_telemetry_clients(mongo_telemetry_client_repo, clients_seed, overwrite_existing)

        rules_db = db_manager.get_rules_db()
        rules_collection = rules_db["heuristic_rules"]
        existing_rules = await rules_collection.count_documents({})

        if force_rules:
            await rules_db["heuristic_rules"].delete_many({})
            await rules_db["rule_versions"].delete_many({})
            await rules_db["rule_audit_log"].delete_many({})
            if db_manager.redis_client_window_telemetry:
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