import os
from pathlib import Path

import sentry_sdk
from fastapi import FastAPI
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.utils.api import register_routes
from app.utils.config import settings
from app.utils.exception_handler import (
    http_exception_handler,
    pydantic_validation_exception_handler,
    validation_exception_handler,
)
from app.utils.response import success_response

from .utils.logging import LogLevels, configure_logging

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    send_default_pii=True,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="FASTAPI",
        description="FASTAPI POSTGRES TEMPLATE",
        version="1.0.0",
        debug=settings.DEBUG,
    )

    configure_logging(log_level=LogLevels.info)

    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, pydantic_validation_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API health check endpoint
    @app.get("/api/health")
    async def health_check():
        return JSONResponse(
            content=success_response(
                data={"status": "ok", "message": "API is running"},
                meta_data={"version": "1.0.0", "timestamp": "2024-07-24T10:00:00Z"},
            )
        )

    # Register API routes
    register_routes(app)

    # Mount static frontend files if the directory exists
    frontend_dir = Path(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    )
    if frontend_dir.exists():
        app.mount(
            "/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend"
        )

    return app


app = create_app()
