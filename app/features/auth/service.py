from app.models.user import User
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from .schema import TokenResponse, UserCreate
from fastapi.security import OAuth2PasswordBearer
from app.utils.security import hash_password, verify_password, create_access_token, verify_access_token
from typing import Union
from typing import Optional
import uuid
import hashlib
from datetime import timedelta, datetime, timezone

def get_user_by_id(db: Session, user_id: uuid.UUID) -> Optional[User]:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

def authenticate_user(db: Session, email: str, password: str) -> Union[User, bool]:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        return False
    return user

def create_user_service(db: Session, user_input: UserCreate) -> User:
    existing_user = db.query(User).filter(User.email == user_input.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "invalid data",
                "errors": {
                    "email": ["email already exists"]
                }
            }
        )
    
    if user_input.password != user_input.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "invalid data",
                "errors": {
                    "password": ["passwords do not match"]
                }
            }
        )
    
    user_data = {
        "first_name": user_input.first_name,
        "last_name": user_input.last_name,
        "email": user_input.email,
        "is_active": user_input.is_active,
        "password_hash": hash_password(user_input.password)
    }
    
    db_user = User(**user_data)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def login_service(db: Session, email: str, password: str) -> TokenResponse:
    user = authenticate_user(db, email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.email})
    return TokenResponse(access_token=access_token, token_type="bearer")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def get_current_user(token: str, db: Session) -> User:
    payload = verify_access_token(token)

    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

def change_password_service(
    db: Session, 
    current_user: User, 
    old_password: str, 
    new_password: str
) -> User:
    
    if not verify_password(old_password, current_user.password_hash):
        raise ValueError("Old password is incorrect")

    current_user.password_hash = hash_password(new_password)
    
    try:
        db.commit()
        db.refresh(current_user)
        return current_user
    except Exception as e:
        db.rollback()
        raise ValueError(f"Failed to change password: {str(e)}")
    
async def create_password_reset_token_service(db: Session, email: str) -> Optional[str]:
    user = get_user_by_email(db, email)
    if not user:
        return None
    
    token_data = {
        "id": str(user.id),
        "sub": user.email,
        "type": "password_reset"
    }

    token = create_access_token(token_data, expires_delta=timedelta(minutes=30))
    
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user.last_password_reset_token_hash = token_hash
    
    db.add(user)
    db.commit()
    
    return user, token

async def verify_password_reset_service(db: Session, token: str) -> Optional[User]:
    payload = verify_access_token(token)
    if not payload:
        return False
    if payload.get("type") != "password_reset":
        return False
    
    user_id = uuid.UUID(payload.get("id"))
    user = get_user_by_id(db, user_id)

    if not user:
        return False
    if payload.get("sub") != user.email:
        return False
    
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if user.last_password_reset_token_hash != token_hash:
        return False
    
    return user

async def reset_password_service(db: Session, token: str, new_password: str) -> bool:
    user = await verify_password_reset_service(db, token)
    if not user:
        return False

    user.password_hash = hash_password(new_password)
    user.last_password_reset_token_hash = None
    user.last_password_reset_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    return True