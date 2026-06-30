from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from core_orchestrator.main import app


@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Manejador personalizado que intercepta el bloqueo y envía un JSON estructurado
    """
    return JSONResponse(
        status_code=429,
        content={
            "status": "error",
            "code": "TOO_MANY_REQUESTS",
            "message": "Has superado el límite de peticiones permitido (5 por minuto).",
            "detail": f"Límite excedido: {exc.detail}",
            "retry_after_seconds": 60  # Opcional: puedes indicar cuánto esperar
        },
        headers={"Retry-After": "60"}
    )