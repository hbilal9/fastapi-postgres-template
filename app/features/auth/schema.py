from pydantic import BaseModel, EmailStr, Field, model_validator, ValidationError, ConfigDict
from typing import Optional
import uuid
from datetime import datetime

class UserBase(BaseModel):
    first_name: str = Field(..., description="The user's first name")
    last_name: str = Field(..., description="The user's last name")
    email: EmailStr = Field(..., description="The user's email address")
    is_active: bool = Field(True, description="Indicates if the user is active")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="The user's password")
    
class UserResponse(UserBase):
    id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr
    is_active: bool
    created_at: datetime
    user_data: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)
    
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    
class CookieTokenResponse(BaseModel):
    success: bool = True
    message: str = "Login successful"

class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None
    
class RefreshTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LogoutResponse(BaseModel):
    success: bool = True
    message: str = "Logout successful"

class ResetPasswordVerify(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, description="The new password for the user")

class TwoFASetupResponse(BaseModel):
    qr_code_url: str
    secret: str

class TwoFAVerifyRequest(BaseModel):
    token: str

