"""Unit tests for scripts.migrate_rules_to_mongodb."""

from __future__ import annotations

from pathlib import Path

import pytest

from core_orchestrator.test.conftest import InMemoryRulesStore, SEED_PATH


@pytest.mark.anyio
async def test_migrate_dry_run_does_not_modify_store(monkeypatch):
    from scripts import migrate_rules_to_mongodb as migration

    store = InMemoryRulesStore()
    monkeypatch.setattr(migration, "db", store)

    await migration.migrate(SEED_PATH, dry_run=True)

    assert store.rules == {}
    assert store.versions == {}
    assert store.audit_logs == []


@pytest.mark.anyio
async def test_migrate_force_writes_snapshot_and_report(monkeypatch, tmp_path):
    from scripts import migrate_rules_to_mongodb as migration

    store = InMemoryRulesStore()
    store.seed_from_file()  # Ensure existing data so --force path is exercised.

    docs_dir = tmp_path / "data" / "mongodb"
    docs_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(migration, "db", store)
    monkeypatch.setattr(migration, "ROOT", tmp_path)

    await migration.migrate(SEED_PATH, dry_run=False, force=True)

    assert len(store.rules) >= 4
    assert len(store.versions) >= 1
    assert len(store.audit_logs) >= 1

    snapshot = tmp_path / "data" / "mongodb" / "heuristic_rules_bundle.json"
    report = tmp_path / "data" / "mongodb" / "migration_report.json"

    assert snapshot.exists()
    assert report.exists()

    report_text = report.read_text(encoding="utf-8")
    assert '"rules_db_name": "heuristy"' in report_text
    assert '"cache_key": "rules:active:all"' in report_text


def test_load_seed_reads_expected_file():
    from scripts.migrate_rules_to_mongodb import load_seed

    payload = load_seed(Path(SEED_PATH))

    assert "heuristic_rules" in payload
    assert len(payload["heuristic_rules"]) >= 4

