from fastapi.exceptions import RequestValidationError
from fastapi import Request
from starlette import status
from starlette.responses import JSONResponse
import logging

from core_orchestrator.domain.exceptions.domain_exceptions import DomainException

logger = logging.getLogger("core_orchestrator.exceptions")


def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handles request validation errors by logging detailed error information and returning
    a formatted JSON response with sanitized error details.

    This handler is triggered when a `RequestValidationError` occurs due to invalid input
    data during a request. It logs details such as the affected route, error location,
    message, and type. Sanitizes any byte data in the error details to prevent raw
    byte content from being exposed in logs or responses.

    Arguments:
        request (Request): The HTTP request that caused the validation error
        exc (RequestValidationError): The exception containing validation error details.

    Returns:
        JSONResponse: A response object with HTTP status 422 and a JSON body containing
        sanitized error details.
    """
    errors = exc.errors()
    logger.warning("⚠️ === VALIDATION ERROR DETECTED (422) ===")
    logger.warning(f"Affected route: {request.url.path}")

    for i, error in enumerate(errors, 1):
        campo = " -> ".join(str(x) for x in error.get("loc", []))
        message = error.get("msg")
        type_error = error.get("type")

        logger.warning(f" Error #{i} in field: [{campo}]")
        logger.warning(f"   Reason: {message} (Type: {type_error})")

    logger.warning("==========================================")
    public_errors = []
    for error in errors:
        public_errors.append({
            "field": " -> ".join(str(x) for x in error.get("loc", []) if x != "body"),
            "message": error.get("msg"),
            "type": error.get("type"),
        })

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": public_errors},
    )


def domain_exception_handler(request: Request, exc: DomainException)->JSONResponse:
    """
    Handles domain-related exceptions and generates an appropriate JSON response.

    This function is designed to catch and process exceptions of type DomainException
    that occur during the handling of requests. It logs the details of the exception,
    including the code and message, and returns a JSON response with the relevant
    error information.

    Args:
        request (Request): The incoming HTTP request object, which provides information
            such as the requested URL path
        exc (DomainException): The exception instance representing the domain-related
            error that has been raised. This includes a code and a descriptive message

    Returns:
        JSONResponse: A JSON response with a 400 HTTP status code containing details
        of the domain exception, including its error code and message.
    """
    logger.warning(
        f"⚠️ Domain rule violation at {request.url.path} [{exc.code}]: {exc.message}"
    )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": getattr(exc, "code", "DOMAIN_ERROR"),
            "detail": exc.message,
        },
    )

def unhandled_exception_handler(request: Request, exc: Exception)->JSONResponse:
    """
    Handles unhandled exceptions occurring during request processing.

    This function is an exception handler for unexpected errors that occur
    during the lifecycle of a request. It logs the exception details and returns
    a JSON response with an HTTP status code indicating an internal server error.

    Arguments:
    - request (Request): The HTTP request object that triggered the exception.
    - exc (Exception): The exception instance that was raised.

    Returns:
    JSONResponse: A JSON response with a status code of 500 and a standardized
    error message.
    """
    logger.error("Unhandled exception at %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error."},
    )