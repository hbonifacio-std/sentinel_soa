from fastapi.exceptions import RequestValidationError
from fastapi import Request
from starlette import status
from starlette.responses import JSONResponse

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

    # Retorna la respuesta original a FastAPI para no romper el comportamiento de los clientes
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": errors},
    )