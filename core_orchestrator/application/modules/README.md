# Application modules map

Reorganization by capability (no business logic changes):

- `auth_clients/services/`
  - `auth_service.py`
  - `user_service.py`
  - `telemetry_client_service.py`
- `telemetry/services/`
  - `telemetry_service.py`
  - `telemetry_processing_service.py`
- `analysis_reports/services/`
  - `analysis_service.py`
  - `analytics_service.py`
  - `threat_context_service.py`
  - `rule_service.py`
  - `rules_engine_service.py`
  - `default_rule_validator_service.py`

## Backward compatibility

Legacy imports under `core_orchestrator/application/services/*.py` are kept as compatibility shims that re-export the canonical modules above.

