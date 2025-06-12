from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.utils.api import register_routes
from app.utils.config import settings
from fastapi.exceptions import RequestValidationError, HTTPException
from pydantic import ValidationError
from app.utils.exception_handler import validation_exception_handler, pydantic_validation_exception_handler, http_exception_handler
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .utils.logging import configure_logging, LogLevels


def create_app() -> FastAPI:
    app = FastAPI(
        title="FASTAPI POSTGRES",
        description="FASTAPI POSTGRES TEMPLATE",
        version="1.0.0",
        debug=settings.DEBUG
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
 
    register_routes(app)
    return app

app = create_app()