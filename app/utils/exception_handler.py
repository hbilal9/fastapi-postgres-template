from typing import Dict, List

from fastapi import Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError


def format_validation_errors(errors) -> Dict[str, List[str]]:
    """Convert Pydantic validation errors to custom format"""
    formatted_errors = {}

    for error in errors:
        field_name = error["loc"][-1]  # Get the field name
        error_type = error["type"]

        # Create user-friendly error messages
        if error_type == "missing":
            message = f"{field_name.replace('_', ' ')} field is required"
        elif error_type == "string_too_short":
            min_length = error["ctx"]["min_length"]
            message = f"{field_name.replace('_', ' ')} must be at least {min_length} characters"
        elif error_type == "value_error":
            message = str(error["msg"])
        else:
            message = error["msg"]

        if field_name not in formatted_errors:
            formatted_errors[field_name] = []
        formatted_errors[field_name].append(message)

    return formatted_errors


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Custom handler for validation errors"""
    return JSONResponse(
        status_code=422,
        content={
            "message": "invalid data",
            "errors": format_validation_errors(exc.errors()),
        },
    )


async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
    """Custom handler for Pydantic validation errors"""
    return JSONResponse(
        status_code=422,
        content={
            "message": "invalid data",
            "errors": format_validation_errors(exc.errors()),
        },
    )


async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom handler for HTTP exceptions"""
    # If the detail is already in our custom format, return it directly
    if (
        isinstance(exc.detail, dict)
        and "message" in exc.detail
        and "errors" in exc.detail
    ):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    # Otherwise, return the standard format
    return JSONResponse(
        status_code=exc.status_code, content={"message": str(exc.detail)}
    )
