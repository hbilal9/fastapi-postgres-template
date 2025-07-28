from typing import Any, Dict

from app.services.email.base import BaseEmail


class AccountExistsEmail(BaseEmail):
    @property
    def template_name(self) -> str:
        return "emails/account_exists.html"

    @property
    def subject(self) -> str:
        return "Account Already Exists"

    def get_context(self, **kwargs) -> Dict[str, Any]:
        context = super().get_context(**kwargs)
        required_fields = ["first_name", "reset_password_url", "login_link"]
        for field in required_fields:
            if field not in kwargs:
                raise ValueError(
                    f"Missing required field for AccountExistsEmail: {field}"
                )
        return context
