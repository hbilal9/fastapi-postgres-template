from fastapi import BackgroundTasks

from app.services.email.base import BaseEmail
from app.services.email.email_service import email_service
from app.services.email.types import (
    NotificationEmail,
    PasswordResetEmail,
    VerificationEmail,
    WelcomeEmail,
    AccountExistsEmail,
)

__all__ = [
    "email_service",
    "BaseEmail",
    "PasswordResetEmail",
    "WelcomeEmail",
    "AccountExistsEmail",
    "VerificationEmail",
    "NotificationEmail",
    "send_password_reset_email",
]


async def send_password_reset_email(
    background_tasks: BackgroundTasks, user_email: str, first_name: str, reset_link: str
) -> None:
    email = PasswordResetEmail()
    await email.send(
        email_to=user_email,
        background_tasks=background_tasks,
        first_name=first_name,
        reset_link=reset_link,
    )
