from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi import Request
from starlette import status
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import json

import logging

logger = logging.getLogger("core_orchestrator.exceptions")


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Captura los errores de validación de los modelos (Error 422)
    e imprime detalladamente qué campo y por qué falló.
    """
    errors = exc.errors()
    
    # Imprime una alerta visual clara en los logs de la consola
    logger.error("❌ === DETECTADO ERROR DE VALIDACIÓN (422) ===")
    logger.error(f"Ruta afectada: {request.url.path}")

    for i, error in enumerate(errors, 1):
        # El "loc" indica la ruta exacta del campo en el JSON (ej: ['body', 0, 'network'])
        campo = " -> ".join(str(x) for x in error.get("loc", []))
        mensaje = error.get("msg")
        tipo_error = error.get("type")

        logger.error(f" Error #{i} en el campo: [{campo}]")
        logger.error(f"   Motivo: {mensaje} (Tipo: {tipo_error})")

    logger.error("==========================================")

    # Retorna la respuesta - sanitiza los bytes
    sanitized_errors = []
    for error in errors:
        e_copy = dict(error)
        if isinstance(e_copy.get("input"), bytes):
            e_copy["input"] = f"<{len(e_copy['input'])} bytes>"
        sanitized_errors.append(e_copy)
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(sanitized_errors)},
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Handles unanticipated runtime exceptions without leaking internal details.
    """
    logger.error("Unhandled exception at %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error."},
    )