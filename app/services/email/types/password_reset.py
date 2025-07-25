from typing import Any, Dict

from app.services.email.base import BaseEmail


class PasswordResetEmail(BaseEmail):
    @property
    def template_name(self) -> str:
        return "emails/password_reset.html"

    @property
    def subject(self) -> str:
        return "Reset Your Password"

    def get_context(self, **kwargs) -> Dict[str, Any]:
        context = super().get_context(**kwargs)
        required_fields = ["first_name", "reset_link"]
        for field in required_fields:
            if field not in kwargs:
                raise ValueError(
                    f"Missing required field for PasswordResetEmail: {field}"
                )
        return context
