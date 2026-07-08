import sys
from pathlib import Path
# add project root to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.telemetry import router
from core_orchestrator.infrastructure.api.dependencies import get_telemetry_service, get_telemetry_processing_service, get_agent_runner
from core_orchestrator.infrastructure.security.dependencies import verify_api_key_header
from core_orchestrator.test.infrastructure.api.v1.test_telemetry_endpoints import dummy_auth_context, dummy_event
import unittest.mock as mock

app = FastAPI()
app.include_router(router)
app.dependency_overrides[get_telemetry_service] = lambda: mock.AsyncMock()
app.dependency_overrides[get_telemetry_processing_service] = lambda: mock.AsyncMock()
app.dependency_overrides[get_agent_runner] = lambda: mock.AsyncMock()
app.dependency_overrides[verify_api_key_header] = lambda: dummy_auth_context

client = TestClient(app, raise_server_exceptions=True)
resp = client.post('/ingest/batch', json=[dummy_event.model_dump(mode='json')])
print('STATUS', resp.status_code)
print(resp.text)
