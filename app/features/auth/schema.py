from pydantic import BaseModel, EmailStr, Field, model_validator, ValidationError, ConfigDict
from typing import Literal
import uuid
from datetime import datetime

class UserBase(BaseModel):
    first_name: str = Field(..., description="The user's first name")
    last_name: str = Field(..., description="The user's last name")
    email: EmailStr = Field(..., description="The user's email address")
    is_active: bool = Field(True, description="Indicates if the user is active")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="The user's password")
    confirm_password: str = Field(..., min_length=8, description="The user's password confirmation")
  
    @model_validator(mode='after')
    def check_passwords_match(self):
        if self.password != self.confirm_password:
            raise ValidationError.from_exception_data(
                title="Validation Error",
                line_errors=[
                    {
                        'type': 'value_error',
                        'loc': ('password',),
                        'msg': 'passwords do not match',
                        'input': {'password': self.password, 'confirm_password': self.confirm_password},
                        'ctx': {'error': ValueError('passwords do not match')}
                    }
                ]
            )
        return self
    
class UserResponse(UserBase):
    id: uuid.UUID
    first_name: str
    last_name: str
    email: EmailStr
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
    
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ResetPasswordVerify(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, description="The new password for the user")