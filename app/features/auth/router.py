from fastapi import APIRouter, status, Request, Depends, BackgroundTasks, Response, Query
from .service import (
    create_user_service,
    login_service,
    create_password_reset_token_service,
    verify_password_reset_service,
    reset_password_service,
    refresh_access_token,
)
from .schema import (
    UserCreate,
    UserResponse,
    TokenResponse,
    ResetPasswordVerify,
    CookieTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    LogoutResponse,
)
from fastapi.security import OAuth2PasswordRequestForm
from app.utils.dependencies import CurrentUser, DbSession
from app.utils.rate_limiter import limiter
from app.services.email import send_password_reset_email
from app.utils.security import (
    set_auth_cookies,
    delete_auth_cookies,
    get_token_from_cookies,
)
from fastapi import HTTPException
from app.utils.config import settings
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.models.user import User
from sqlalchemy import cast, JSON
from sqlalchemy.dialects.postgresql import JSONB
from .service import generate_verification_token

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.get("/verify-email", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def verify_email(
    request: Request, 
    db: DbSession,
    token: str = Query(..., description="Email verification token")
):
    
    user = db.query(User).filter(
        cast(User.user_data, JSONB)["verification_token"].astext == token
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )
    if user.is_user_confirmed:
        return {"message": "Email already verified. You can now log in."}
    
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
    
    db.commit()
    
    return {"message": "Email verified successfully. You can now log in."}


@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def login(
    request: Request, db: DbSession, form_data: OAuth2PasswordRequestForm = Depends()
):
    return login_service(db, form_data.username, form_data.password)


@router.post(
    "/login", response_model=CookieTokenResponse, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
async def login_with_cookies(
    request: Request,
    response: Response,
    db: DbSession,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    token_data = login_service(db, form_data.username, form_data.password)
    set_auth_cookies(response, token_data.access_token, token_data.refresh_token)
    return CookieTokenResponse(message="Login successful")

@router.post("/refresh", response_model=RefreshTokenResponse)
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
    refresh_data: RefreshTokenRequest = None,
):
    refresh_token = None
    if refresh_data and refresh_data.refresh_token:
        refresh_token = refresh_data.refresh_token
    else:
        refresh_token = get_token_from_cookies(request, "refresh_token")

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is required",
        )

    new_access_token = refresh_access_token(db, refresh_token)
    if get_token_from_cookies(request, "refresh_token"):
        set_auth_cookies(response, new_access_token, refresh_token)

    return RefreshTokenResponse(access_token=new_access_token)


@router.post("/logout", response_model=LogoutResponse)
async def logout(response: Response):
    delete_auth_cookies(response)
    return LogoutResponse()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(request: Request, user: UserCreate, db: DbSession, background_tasks: BackgroundTasks):
    db_user = create_user_service(db=db, user_input=user, background_tasks=background_tasks)
    if settings.USER_VERIFICATION_CHECK:
        db_user.user_data = {"message": "Verification email sent. Please check your inbox to verify your account."}
    
    return db_user

@router.get("/verification-status", status_code=status.HTTP_200_OK)
async def verification_status(current_user: CurrentUser):
    return {
        "is_verified": current_user.is_user_confirmed,
        "verification_required": settings.USER_VERIFICATION_CHECK
    }

@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_current_user(current_user: CurrentUser):
    return current_user


@router.get("/test/reset-password-email", status_code=status.HTTP_200_OK)
async def test_password_reset_email(background_tasks: BackgroundTasks):
    email = "mtalha@texagon.io"
    first_name = "Talha"
    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    reset_link = f"{frontend_url}/auth/reset-password?token=test-token-12345"
    
    await send_password_reset_email(
        background_tasks,
        user_email=email,
        first_name=first_name,
        reset_link=reset_link,
    )
    
    return {
        "message": f"Test password reset email sent to {email}",
        "reset_link": reset_link,
    }


@router.post("/reset-password/request", status_code=status.HTTP_200_OK)
async def create_password_reset_token(
    request: Request, db: DbSession, email: str, background_tasks: BackgroundTasks
):
    user, token = await create_password_reset_token_service(db, email)

    if token:
        frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
        reset_link = f"{frontend_url}/auth/reset-password?token={token}"
        first_name = user.first_name if user else ""

        await send_password_reset_email(
            background_tasks,
            user_email=email,
            first_name=first_name,
            reset_link=reset_link,
        )

    return {
        "message": "If an account with that email exists, a password reset link has been sent to your email."
    }


@router.post("/reset-password")
async def reset_password(request: Request, db: DbSession, data: ResetPasswordVerify):
    user = await verify_password_reset_service(db, data.token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    success = await reset_password_service(db, data.token, data.new_password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password",
        )
    return {"message": "Password reset successfully"}
