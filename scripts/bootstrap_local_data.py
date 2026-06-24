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
from typing import Optional, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_orchestrator.models.telemetry_client import TelemetryBootstrapSummary  # noqa: E402
from core_orchestrator.services.bootstrap_service import (  # noqa: E402
    DEFAULT_TELEMETRY_CLIENTS_SEED,
    DEFAULT_USERS_SEED,
    bootstrap_service,
)
from core_orchestrator.services.database import db  # noqa: E402
from core_orchestrator.services.rules_engine import get_rules_engine  # noqa: E402

logger = logging.getLogger("bootstrap_local_data")
DEFAULT_RULES_SEED = ROOT / "data" / "mongodb" / "heuristic_rules.json"


async def bootstrap(
    users_seed: Path,
    clients_seed: Path,
    overwrite_existing: bool,
    force_rules: bool,
) -> TelemetryBootstrapSummary:
    await db.connect_to_mongo()
    await db.connect_to_redis()

    result: Optional[TelemetryBootstrapSummary] = None

    try:
        await bootstrap_service.ensure_indexes()

        users_summary = await bootstrap_service.seed_users(
            seed_path=users_seed,
            overwrite_existing=overwrite_existing,
        )
        clients_summary = await bootstrap_service.seed_telemetry_clients(
            seed_path=clients_seed,
            overwrite_existing=overwrite_existing,
        )

        rules_db = db.get_rules_db()
        rules_collection = rules_db["heuristic_rules"]
        existing_rules = await rules_collection.count_documents({})

        if force_rules:
            await rules_db["heuristic_rules"].delete_many({})
            await rules_db["rule_versions"].delete_many({})
            await rules_db["rule_audit_log"].delete_many({})
            await db.invalidate_rules_cache()
            existing_rules = 0
            logger.info("Existing heuristic rules cleared before reseed.")

        rules_engine = get_rules_engine()
        await rules_engine.initialize()
        total_rules = await rules_collection.count_documents({})

        cache_summary = await bootstrap_service.warm_authorized_clients_cache()

        result = TelemetryBootstrapSummary(
            users_created=users_summary.users_created,
            users_skipped=users_summary.users_skipped,
            users_updated=users_summary.users_updated,
            clients_created=clients_summary.clients_created,
            clients_skipped=clients_summary.clients_skipped,
            clients_updated=clients_summary.clients_updated,
            rules_seeded=existing_rules == 0 and total_rules > 0,
            cache_warmed_clients=cache_summary.cache_warmed_clients,
        )

        logger.info("Bootstrap completed successfully.")
    finally:
        await db.close_mongo_connection()
        await db.close_redis_connection()

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




