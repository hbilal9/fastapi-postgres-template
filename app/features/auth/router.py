from fastapi import APIRouter, status, Request, Depends, BackgroundTasks, Response
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
from app.services.email_service import send_password_reset_email
from app.utils.security import (
    set_auth_cookies,
    delete_auth_cookies,
    get_token_from_cookies,
)
from fastapi import HTTPException
import os

router = APIRouter(prefix="/auth", tags=["Auth"])


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
    """Endpoint to refresh an access token using a refresh token"""
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
    """Logout endpoint that clears authentication cookies"""
    delete_auth_cookies(response)
    return LogoutResponse()


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(request: Request, db: DbSession, user: UserCreate):
    user = create_user_service(db, user)
    if user:
        return {
            "message": "Account created successfully. You can now log in.",
        }
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to create user account",
    )


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def get_user_profile(request: Request, user: CurrentUser):
    return user


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
