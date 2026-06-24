from __future__ import annotations

import json
import logging
from pathlib import Path

from core_orchestrator.models.telemetry_client import (
    TelemetryBootstrapSummary,
    TelemetryClientCreate,
)
from core_orchestrator.models.user import UserCreate
from core_orchestrator.services.telemetry_client_service import telemetry_client_service
from core_orchestrator.services.user_service import UserService

logger = logging.getLogger("core_orchestrator.services.bootstrap_service")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_USERS_SEED = ROOT / "data" / "users_seed.json"
DEFAULT_TELEMETRY_CLIENTS_SEED = ROOT / "data" / "telemetry_clients_seed.json"


class BootstrapService:
    @staticmethod
    def _load_seed(path: Path):
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)

    async def ensure_indexes(self) -> None:
        await UserService.ensure_indexes()
        await telemetry_client_service.ensure_indexes()

    async def seed_users(
        self,
        seed_path: Path = DEFAULT_USERS_SEED,
        overwrite_existing: bool = False,
    ) -> TelemetryBootstrapSummary:
        summary = TelemetryBootstrapSummary()
        users_data = self._load_seed(seed_path)

        for user_data in users_data:
            user, created = await UserService.seed_user(
                UserCreate(**user_data),
                overwrite_existing=overwrite_existing,
            )
            if created:
                summary.users_created += 1
            elif overwrite_existing:
                summary.users_updated += 1
            else:
                summary.users_skipped += 1
            logger.info("Bootstrap user ready: %s (role=%s)", user.username, user.role)
        return summary

    async def seed_telemetry_clients(
        self,
        seed_path: Path = DEFAULT_TELEMETRY_CLIENTS_SEED,
        overwrite_existing: bool = False,
    ) -> TelemetryBootstrapSummary:
        summary = TelemetryBootstrapSummary()
        clients_data = self._load_seed(seed_path)

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
            logger.info("Bootstrap telemetry client ready: %s -> %s", client.client_id, client.source_id)
        return summary

    async def warm_authorized_clients_cache(self) -> TelemetryBootstrapSummary:
        summary = TelemetryBootstrapSummary()
        summary.cache_warmed_clients = await telemetry_client_service.warm_cache()
        return summary

    async def run_startup_bootstrap(self) -> TelemetryBootstrapSummary:
        await self.ensure_indexes()
        users_summary = await self.seed_users(overwrite_existing=False)
        clients_summary = await self.seed_telemetry_clients(overwrite_existing=False)
        cache_summary = await self.warm_authorized_clients_cache()

        return TelemetryBootstrapSummary(
            users_created=users_summary.users_created,
            users_skipped=users_summary.users_skipped,
            users_updated=users_summary.users_updated,
            clients_created=clients_summary.clients_created,
            clients_skipped=clients_summary.clients_skipped,
            clients_updated=clients_summary.clients_updated,
            cache_warmed_clients=cache_summary.cache_warmed_clients,
        )


bootstrap_service = BootstrapService()
