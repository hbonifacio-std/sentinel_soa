#!/usr/bin/env python3
"""
Migrate heuristic rules from seed JSON into MongoDB and warm Redis cache.

Usage:
    python scripts/migrate_rules_to_mongodb.py
    python scripts/migrate_rules_to_mongodb.py --seed data/mongodb/heuristic_rules.json
    python scripts/migrate_rules_to_mongodb.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_orchestrator.domain.models.rules import (  # noqa: E402
    HeuristicRule,
    RuleAuditLog,
    RuleVersion,
    hash_version,
    rules_to_bundle,
)
from core_orchestrator.services.database_mongo_service import db  # noqa: E402

logger = logging.getLogger("migrate_rules")
DEFAULT_SEED = ROOT / "data" / "mongodb" / "heuristic_rules.json"


def load_seed(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


async def migrate(seed_path: Path, dry_run: bool = False, force: bool = False) -> None:
    seed = load_seed(seed_path)
    rules = [HeuristicRule(**doc) for doc in seed.get("heuristic_rules", [])]
    versions = [RuleVersion(**doc) for doc in seed.get("rule_versions", [])]
    audit_entries = [RuleAuditLog(**doc) for doc in seed.get("rule_audit_log", [])]

    version_hash = versions[0].version_hash if versions else hash_version(rules)
    bundle = rules_to_bundle(rules, version_hash=version_hash)

    logger.info("Seed file: %s", seed_path)
    logger.info("Rules to migrate: %d", len(rules))
    logger.info("Version hash: %s", version_hash)
    logger.info("Rules MongoDB target: %s", db.get_rules_db_name())
    logger.info(
        "Bundle summary: ua=%d uris=%d sql=%d traversal=%d",
        len(bundle.malicious_ua_keywords),
        len(bundle.sensitive_uris),
        len(bundle.sql_injection_patterns),
        len(bundle.path_traversal_patterns),
    )

    if dry_run:
        logger.info("Dry run complete — no database changes made.")
        return

    await db.connect_to_mongo()
    await db.connect_to_redis()

    try:
        mongo = db.get_rules_db()
        existing = await mongo["heuristic_rules"].count_documents({})

        if existing > 0 and not force:
            logger.warning(
                "Collection 'heuristic_rules' already has %d documents. "
                "Use --force to replace.",
                existing,
            )
            return

        if force and existing > 0:
            await mongo["heuristic_rules"].delete_many({})
            await mongo["rule_versions"].delete_many({})
            await mongo["rule_audit_log"].delete_many({})
            logger.info("Cleared existing rule collections (--force).")

        for rule in rules:
            await db.insert(rule)
            logger.info("  Inserted rule: %s", rule.rule_id)

        for version in versions:
            await db.create_version(version)
            logger.info("  Inserted version: %s", version.version_hash)

        for entry in audit_entries:
            await db.log_rule_action(
                action=entry.action,
                rule_id=entry.rule_id,
                user=entry.user,
                changes=entry.changes,
                reason=entry.reason,
                status=entry.status,
                ip_address=entry.ip_address,
            )

        await db.cache_rules(bundle)
        logger.info("Rules cached in Redis DB3.")

        bundle_snapshot_path = ROOT / "data" / "mongodb" / "heuristic_rules_bundle.json"
        bundle_snapshot_path.write_text(json.dumps(bundle.to_cache_dict(), indent=2), encoding="utf-8")
        logger.info("Rules bundle snapshot written to %s", bundle_snapshot_path)

        report = {
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "rules_count": len(rules),
            "version_hash": version_hash,
            "rules_db_name": db.get_rules_db_name(),
            "collections": ["heuristic_rules", "rule_versions", "rule_audit_log"],
            "cache_key": "rules:active:all",
        }
        report_path = ROOT / "data" / "mongodb" / "migration_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logger.info("Migration report written to %s", report_path)
        logger.info("Migration completed successfully.")
    finally:
        await db.close_mongo_connection()
        await db.close_redis_connection()


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate heuristic rules to MongoDB")
    parser.add_argument("--seed", type=Path, default=DEFAULT_SEED, help="Path to seed JSON")
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing")
    parser.add_argument("--force", action="store_true", help="Replace existing collections")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    if not args.seed.exists():
        logger.error("Seed file not found: %s", args.seed)
        sys.exit(1)

    asyncio.run(migrate(args.seed, dry_run=args.dry_run, force=args.force))


if __name__ == "__main__":
    main()
