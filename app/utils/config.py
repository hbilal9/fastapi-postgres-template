import os
from functools import lru_cache
from typing import Literal, Optional

from dotenv import load_dotenv

load_dotenv(override=True)


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "FastAPI Postgres Template")
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    # TODO : Change this to Orginal Domain
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    USER_VERIFICATION_CHECK: bool = (
        os.getenv("USER_VERIFICATION_CHECK", "True").lower() == "true"
    )
    USER_VERIFICATION_EXPIRE_MINUTES: int = int(
        os.getenv("USER_VERIFICATION_EXPIRE_MINUTES", "3600")
    )  # 1 hour

    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()

    COOKIE_SECURE: bool = ENVIRONMENT in ["production", "staging"]
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = (
        "strict" if ENVIRONMENT == "production" else "lax"
    )

    # Email Settings
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = (
        int(os.getenv("SMTP_PORT", "0")) if os.getenv("SMTP_PORT") else None
    )
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    EMAILS_FROM_EMAIL: Optional[str] = os.getenv("EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: Optional[str] = os.getenv("EMAILS_FROM_NAME", APP_NAME)

    @property
    def DATABASE_URL(self) -> str:
        DATABASE_NAME = os.getenv("DATABASE_NAME")
        DATABASE_USER = os.getenv("DATABASE_USER")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_PORT = os.getenv("DATABASE_PORT")
        user_pass = f"{DATABASE_USER}:{DATABASE_PASSWORD}"
        host_port = f"{DATABASE_HOST}:{DATABASE_PORT}"
        db_driver = "postgresql+asyncpg"
        if not DATABASE_NAME or not DATABASE_USER or not DATABASE_PASSWORD:
            raise ValueError("Database configuration is incomplete.")
        return f"{db_driver}://{user_pass}@{host_port}/{DATABASE_NAME}"

    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()
