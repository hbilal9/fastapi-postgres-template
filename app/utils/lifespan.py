from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.schedulers import scheduler

from .logging import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan_handler(app: FastAPI):
    """
    Handles startup and shutdown events for the FastAPI application.
    """
    try:
        logger.info("Application startup initiated (via lifespan).")
        scheduler.start()
        logger.info("Scheduler started successfully.")
        yield
        logger.info("Application shutdown initiated (via lifespan).")
        scheduler.shutdown()
        logger.info("Scheduler shut down successfully.")
    except Exception as e:
        logger.error(f"Lifespan handler error: {e}")
        raise
