"""
conftest.py — Ruta raíz de los tests de API.

Deshabilita el rate-limiter (slowapi) para todos los tests de la API.

El decorador @limiter.limit captura el objeto limiter en tiempo de
decoración, y su async_wrapper hace dos cosas:
  1. llama self._check_request_limit(request, func, False)   <- parcheamos esto
  2. lee request.state.view_rate_limit tras el endpoint       <- debemos setearlo

Por eso el side_effect también fija request.state.view_rate_limit = None.
"""
import pytest
from unittest.mock import patch
from core_orchestrator.infrastructure.api.rate_limiter import limiter as _the_limiter


def _noop_check_limit(request, endpoint, *args, **kwargs):
    """Reemplaza _check_request_limit: no verifica límites y establece el atributo de estado."""
    request.state.view_rate_limit = None


@pytest.fixture(autouse=True, scope="session")
def disable_rate_limiter():
    """Neutralise slowapi rate limits so no Redis connection is needed in tests."""
    with patch.object(_the_limiter, "_check_request_limit", side_effect=_noop_check_limit):
        yield
