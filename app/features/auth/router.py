from fastapi import APIRouter, status, Request, Depends, BackgroundTasks
from .service import create_user_service, login_service, create_password_reset_token_service, verify_password_reset_service, reset_password_service
from .schema import UserCreate, UserResponse, TokenResponse, ResetPasswordVerify
from fastapi.security import OAuth2PasswordRequestForm
from app.utils.dependencies import CurrentUser, DbSession
from app.utils.rate_limiter import limiter
from app.services.email_service import send_password_reset_email
from fastapi import HTTPException
import os

router = APIRouter(
    prefix="/auth",
    tags=["Auth"]
)

@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def login(
    request: Request,
    db: DbSession,
    form_data: OAuth2PasswordRequestForm = Depends()
    ):
    return login_service(db, form_data.username, form_data.password)

@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    db: DbSession,
    user: UserCreate
):
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
    request: Request,
    db: DbSession,
    email: str,
    background_tasks: BackgroundTasks
):
    user, token = await create_password_reset_token_service(db, email)

    if token:
        frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
        reset_link = f"{frontend_url}/auth/reset-password?token={token}"
        first_name = user.first_name if user else ""

        await send_password_reset_email(background_tasks, user_email=email, first_name=first_name, reset_link=reset_link)

    return {
        "message": "If an account with that email exists, a password reset link has been sent to your email."}

@router.post('/reset-password')
async def reset_password(
    request: Request,
    db: DbSession,
    data: ResetPasswordVerify
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
    return {"message": "Password reset successfully"}