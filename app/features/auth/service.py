from app.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import JSON, cast
from fastapi import HTTPException, status, Request, BackgroundTasks
from .schema import TokenResponse, UserCreate, LoginRequest
from fastapi.security import OAuth2PasswordBearer
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    verify_refresh_token,
    get_token_from_cookies,
    create_refresh_token,
)
from app.utils.config import settings
from app.services.email import VerificationEmail
from typing import Union, Tuple
from typing import Optional
import uuid
import secrets
import hashlib
from datetime import timedelta, datetime, timezone
import pyotp
import qrcode
import io
import base64

USER_NOT_FOUND_ERROR = "User not found"


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> Optional[User]:
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=USER_NOT_FOUND_ERROR
        )
    return user

async def find_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        return None
    return user

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    user = await find_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=USER_NOT_FOUND_ERROR
        )
    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> Union[User, bool]:
    user = await find_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash):
        return False
    return user


def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


async def create_user_service(
    db: AsyncSession, user_input: UserCreate, background_tasks: BackgroundTasks
) -> User:
    existing_user = await find_user_by_email(db, user_input.email)

    if existing_user:
        if settings.USER_VERIFICATION_CHECK and not existing_user.is_user_confirmed:
            verification_token = generate_verification_token()
            expiration_time = datetime.now(timezone.utc) + timedelta(
                minutes=settings.USER_VERIFICATION_EXPIRE_MINUTES
            )
            if not existing_user.user_data:
                existing_user.user_data = {}

            existing_user.user_data["verification_token"] = verification_token
            existing_user.user_data["verification_expiry"] = expiration_time.isoformat()
            await db.commit()

            verification_url = f"{settings.FRONTEND_URL}/auth/verify?token={verification_token}"
            email = VerificationEmail()
            background_tasks.add_task(
                email.send,
                email_to=existing_user.email,
                first_name=existing_user.first_name,
                verification_link=verification_url,
            )
            return existing_user
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists.",
            )

    user_data = {
        "first_name": user_input.first_name,
        "last_name": user_input.last_name,
        "email": user_input.email,
        "is_active": True,
        "password_hash": hash_password(user_input.password),
        "is_user_confirmed": not settings.USER_VERIFICATION_CHECK,
        "user_data": {},
    }

    if settings.USER_VERIFICATION_CHECK:
        verification_token = generate_verification_token()
        expiration_time = datetime.now(timezone.utc) + timedelta(
            minutes=settings.USER_VERIFICATION_EXPIRE_MINUTES
        )
        user_data["user_data"] = {
            "verification_token": verification_token,
            "verification_expiry": expiration_time.isoformat(),
            "verified": False,
        }
        verification_url = f"{settings.FRONTEND_URL}/auth/verify?token={verification_token}"
        email = VerificationEmail()
        background_tasks.add_task(
            email.send,
            email_to=user_input.email,
            first_name=user_input.first_name,
            verification_link=verification_url,
        )

    db_user = User(**user_data)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def login_service(db: AsyncSession, user_input: LoginRequest) -> TokenResponse:
    user = await authenticate_user(db, email=user_input.email, password=user_input.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if settings.USER_VERIFICATION_CHECK and not user.is_user_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required. Please check your email inbox and verify your account.",
        )
    
    if user.twofa_enabled:
        if not user_input.twofa_token or not check_2fa_token(user, user_input.twofa_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="2FA token required or invalid",
            )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


async def get_current_user(token: str, db: AsyncSession) -> User:
    payload = verify_access_token(token)

    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")

    user = await get_user_by_email(db, email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=USER_NOT_FOUND_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_user_from_cookie(request: Request, db: AsyncSession) -> User:
    token = get_token_from_cookies(request, "access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await get_current_user(token, db)


async def refresh_access_token(db: AsyncSession, refresh_token: str) -> str:
    payload = verify_refresh_token(refresh_token)

    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    user = await db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_access_token = create_access_token(data={"sub": user.email})
    return new_access_token


async def change_password_service(
    db: AsyncSession, current_user: User, old_password: str, new_password: str
) -> User:

    if not verify_password(old_password, current_user.password_hash):
        raise ValueError("Old password is incorrect")

    current_user.password_hash = hash_password(new_password)

    try:
        await db.commit()
        await db.refresh(current_user)
        return current_user
    except Exception as e:
        await db.rollback()
        raise ValueError(f"Failed to change password: {str(e)}")


async def create_password_reset_token_service(
    db: AsyncSession, email: str
) -> Tuple[Optional[User], Optional[str]]:
    user = None
    try:
        user = await get_user_by_email(db, email)
    except HTTPException:
        return None, None

    token_data = {"id": str(user.id), "sub": user.email, "type": "password_reset"}

    token = create_access_token(token_data, expires_delta=timedelta(minutes=30))

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user.last_password_reset_token_hash = token_hash

    await db.add(user)
    await db.commit()

    return user, token


async def verify_password_reset_service(db: AsyncSession, token: str) -> Optional[User]:
    payload = verify_access_token(token)
    if not payload:
        return False
    if payload.get("type") != "password_reset":
        return False

    user_id = uuid.UUID(payload.get("id"))
    user = await get_user_by_id(db, user_id)

    if not user:
        return False
    if payload.get("sub") != user.email:
        return False

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if user.last_password_reset_token_hash != token_hash:
        return False

    return user


async def reset_password_service(db: AsyncSession, token: str, new_password: str) -> bool:
    user = await verify_password_reset_service(db, token)
    if not user:
        return False

    user.password_hash = hash_password(new_password)
    user.last_password_reset_token_hash = None
    user.last_password_reset_at = datetime.now(timezone.utc)
    await db.add(user)
    await db.commit()
    return True

async def setup_2fa(db: AsyncSession, current_user: User) -> dict:
    result = await db.execute(select(User).filter(User.id == current_user.id))
    user = result.scalar_one()
    if not user.twofa_secret:
        secret = pyotp.random_base32()
        user.twofa_secret = secret
        await db.commit()
    else:
        secret = user.twofa_secret

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name=settings.APP_NAME
    )

    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    qr_code_url = f"data:image/png;base64,{qr_b64}"

    return secret, qr_code_url


async def verify_2fa( db: AsyncSession, current_user: User,token: str) -> dict:
    result = await db.execute(select(User).filter(User.id == current_user.id))
    user = result.scalar_one()
    if not user.twofa_secret:
        raise HTTPException(status_code=400, detail="2FA not set up")
    totp = pyotp.TOTP(user.twofa_secret)
    if totp.verify(token):
        user.twofa_enabled = True
        await db.commit()
        return {"message": "2FA enabled successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid 2FA token")

async def check_2fa_token(user: User, token: str) -> bool:
    if not user.twofa_enabled or not user.twofa_secret:
        return True  # 2FA not enabled, so always pass
    totp = pyotp.TOTP(user.twofa_secret)
    return totp.verify(token)

async def verify_email_service(db: AsyncSession, token: str) -> str:
    stmt = select(User).filter(
        cast(User.user_data, JSON)["verification_token"].as_string() == token
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )
    if user.is_user_confirmed:
        return "Email already verified. You can now log in."
    if settings.USER_VERIFICATION_CHECK and user.user_data and "verification_expiry" in user.user_data:
        expiry_str = user.user_data.get("verification_expiry")
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if datetime.now(timezone.utc) > expiry:
                new_token = generate_verification_token()
                new_expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.USER_VERIFICATION_EXPIRE_MINUTES)
                user.user_data["verification_token"] = new_token
                user.user_data["verification_expiry"] = new_expiry.isoformat()
                db.commit()
                print(f"New verification token for {user.email}: {new_token}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Verification token expired. A new token has been sent to your email."
                )
        except ValueError:
            pass
    user.is_user_confirmed = True
    if user.user_data:
        user.user_data["verified"] = True
        user.user_data["verified_at"] = datetime.now(timezone.utc).isoformat()
    await db.commit()
    return "Email verified successfully. You can now log in."