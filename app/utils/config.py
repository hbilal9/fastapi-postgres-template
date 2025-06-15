import os
from functools import lru_cache
from dotenv import load_dotenv
from typing import Optional, Literal

load_dotenv(override=True)


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "Sophie CRM")
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

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


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()
