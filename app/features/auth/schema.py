import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBaseSchema(BaseModel):
    first_name: str = Field(..., description="The user's first name")
    last_name: str = Field(..., description="The user's last name")
    email: EmailStr = Field(..., description="The user's email address")
    is_active: bool = Field(True, description="Indicates if the user is active")


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str
    twofa_token: Optional[str] = None


class UserCreateSchema(UserBaseSchema):
    password: str = Field(..., min_length=8, description="The user's password")


class UserResponseSchema(UserBaseSchema):
    id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr
    is_active: bool
    created_at: datetime
    user_data: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int


class CookieTokenResponseSchema(BaseModel):
    success: bool = True
    message: str = "Login successful"


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: Optional[str] = None


class RefreshTokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LogoutResponseSchema(BaseModel):
    success: bool = True
    message: str = "Logout successful"


class ResetPasswordVerifySchema(BaseModel):
    token: str
    new_password: str = Field(
        ..., min_length=8, description="The new password for the user"
    )


class TwoFASetupResponseSchema(BaseModel):
    qr_code_url: str
    secret: str


class TwoFAVerifyRequestSchema(BaseModel):
    token: str
