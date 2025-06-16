from typing import Dict, Any
from app.services.email.base import BaseEmail


class WelcomeEmail(BaseEmail):
    @property
    def template_name(self) -> str:
        return "emails/welcome.html"

    @property
    def subject(self) -> str:
        return "Welcome to Our Platform!"

    def get_context(self, **kwargs) -> Dict[str, Any]:
        context = super().get_context(**kwargs)
        required_fields = ["first_name"]
        for field in required_fields:
            if field not in kwargs:
                raise ValueError(f"Missing required field for WelcomeEmail: {field}")
        return context
