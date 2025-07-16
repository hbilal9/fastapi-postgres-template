from fastapi import APIRouter, FastAPI

from app.features.auth.router import router as auth_router

# Create API router with prefix
api_router = APIRouter(prefix="/api")

# Include feature routers
api_router.include_router(auth_router)


def register_routes(app: FastAPI):
    # Include the API router which contains all API endpoints
    app.include_router(api_router)
