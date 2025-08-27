import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import Request, Response
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.utils.config import settings

from .constants import ACCESS_TOKEN_NAME

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire, "token_type": "access"})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

    to_encode.update({"exp": expire, "token_type": "refresh"})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if "exp" in payload and datetime.fromtimestamp(
            payload["exp"], timezone.utc
        ) < datetime.now(timezone.utc):
            return None
        return payload
    except JWTError:
        return None


def verify_access_token(token: str) -> Optional[Dict]:
    payload = verify_token(token)
    if not payload or payload.get("token_type", "access") != "access":
        return None
    return payload


def verify_refresh_token(token: str) -> Optional[Dict]:
    payload = verify_token(token)
    if not payload or payload.get("token_type") != "refresh":
        return None
    return payload


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    """Set HTTP-only cookies for authentication tokens"""
    response.set_cookie(
        key=ACCESS_TOKEN_NAME,
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,  # True in production
        samesite=settings.COOKIE_SAMESITE,  # "lax" or "strict" in production
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    cookie_params = {
        "key": "refresh_token",
        "value": refresh_token,
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    }

    response.set_cookie(**cookie_params, path="/api/auth/refresh")
    response.set_cookie(**cookie_params, path="/api/auth/logout")


def delete_auth_cookies(response: Response) -> None:
    """Delete authentication cookies"""
    response.delete_cookie(key=ACCESS_TOKEN_NAME, path="/")
    response.delete_cookie(key="refresh_token", path="/api/auth/refresh")
    response.delete_cookie(key="refresh_token", path="/api/auth/logout")


def get_token_from_cookies(
    request: Request,
    token_type: str = ACCESS_TOKEN_NAME,
) -> Optional[str]:
    """Get token from cookies or authorization header"""
    # Try to get from cookies first
    token = request.cookies.get(token_type)

    # If not in cookies, try Authorization header
    if not token and token_type == ACCESS_TOKEN_NAME:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    return token


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
