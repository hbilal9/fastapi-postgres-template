from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.utils.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    token_hash = Column(
        String, unique=True, index=True
    )  # Store hash instead of raw token
    expires_at = Column(DateTime(timezone=True))  # Add timezone=True
    is_revoked = Column(Boolean, default=False)
    created_at = Column(
        DateTime(timezone=True), default=datetime.now(timezone.utc)
    )  # Add timezone=True

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    success = Column(Boolean, default=False)
    ip_address = Column(String)
    user_agent = Column(String)
    created_at = Column(
        DateTime(timezone=True), default=datetime.now(timezone.utc)
    )  # Add timezone=True

    # Relationships
    user = relationship("User", back_populates="login_attempts")
