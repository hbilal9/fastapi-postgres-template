import os

from fastapi import (
    APIRouter,
    BackgroundTasks,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)

from app.services.email import send_password_reset_email
from app.utils.config import settings
from app.utils.dependencies import CurrentUser, DbSession
from app.utils.rate_limiter import limiter
from app.utils.response import StandardResponse, success_response
from app.utils.security import (
    delete_auth_cookies,
    get_token_from_cookies,
    set_auth_cookies,
)

from .schema import (
    CookieTokenResponseSchema,
    LoginRequestSchema,
    LogoutResponseSchema,
    RefreshTokenRequestSchema,
    RefreshTokenResponseSchema,
    ResetPasswordVerifySchema,
    TokenResponseSchema,
    UserCreateSchema,
    UserResponseSchema,
)
from .service import (
    create_password_reset_token_service,
    create_user_service,
    login_service,
    refresh_access_token,
    reset_password_service,
    setup_2fa,
    verify_2fa,
    verify_email_service,
    verify_password_reset_service,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.get(
    "/verify-email", response_model=StandardResponse, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
async def verify_email(
    request: Request,
    db: DbSession,
    token: str = Query(..., description="Email verification token"),
):
    message = await verify_email_service(db, token)
    return success_response(
        data={"message": message},
    )


@router.post("/token", response_model=StandardResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def login(request: Request, db: DbSession, form_data: LoginRequestSchema):
    response = await login_service(db, form_data)
    return success_response(
        data=TokenResponseSchema(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            expires_in=response.expires_in,
        )
    )


@router.post(
    "/login", response_model=CookieTokenResponseSchema, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
async def login_with_cookies(
    request: Request,
    response: Response,
    db: DbSession,
    form_data: LoginRequestSchema,
):
    token_data = await login_service(db, form_data)
    set_auth_cookies(response, token_data.access_token, token_data.refresh_token)
    return CookieTokenResponseSchema(message="Login successful")


@router.post(
    "/refresh", response_model=StandardResponse, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
    refresh_data: RefreshTokenRequestSchema = None,
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

    new_access_token = await refresh_access_token(db, refresh_token)
    if get_token_from_cookies(request, "refresh_token"):
        set_auth_cookies(response, new_access_token, refresh_token)

    return success_response(
        data=RefreshTokenResponseSchema(access_token=new_access_token)
    )


@router.post("/logout", response_model=StandardResponse)
async def logout(response: Response):
    delete_auth_cookies(response)
    return success_response(data=LogoutResponseSchema())


@router.post(
    "/register", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    user: UserCreateSchema,
    db: DbSession,
    background_tasks: BackgroundTasks,
):
    db_user = await create_user_service(
        db=db, user_input=user, background_tasks=background_tasks
    )
    if settings.USER_VERIFICATION_CHECK:
        if not db_user.user_data:
            db_user.user_data = {}
        db_user.user_data["message"] = (
            "Verification email sent. Please check your inbox to verify your account."
        )

    return success_response(data=db_user)


@router.get("/verification-status", status_code=status.HTTP_200_OK)
async def verification_status(current_user: CurrentUser):
    return {
        "is_verified": current_user.is_user_confirmed,
        "verification_required": settings.USER_VERIFICATION_CHECK,
    }


@router.get("/me", response_model=StandardResponse, status_code=status.HTTP_200_OK)
async def get_current_user(current_user: CurrentUser):
    return success_response(data=UserResponseSchema(**current_user.__dict__))


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

    return success_response(
        data={
            "message": f"Test password reset email sent to {email}",
            "reset_link": reset_link,
        }
    )


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

    return success_response(
        data={
            "message": "If an account with that email exists, a password reset link has been sent to your email."
        }
    )


@router.post("/reset-password")
async def reset_password(
    request: Request, db: DbSession, data: ResetPasswordVerifySchema
):
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
    return success_response(
        data={
            "message": "Password reset successful. You can now log in with your new password."
        }
    )


@router.post("/2fa/setup", status_code=status.HTTP_200_OK)
async def setup_twofa(
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )

    secret, qr_code = await setup_2fa(db, current_user)

    return success_response(
        data={"message": "2FA setup successful", "secret": secret, "qr_code": qr_code}
    )


@router.post("/2fa/verify", status_code=status.HTTP_200_OK)
async def verify_twofa(
    request: Request, db: DbSession, current_user: CurrentUser, token: str
):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )

    is_valid = await verify_2fa(db, current_user, token)

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA token"
        )

    return success_response(data={"message": "2FA verification successful"})
