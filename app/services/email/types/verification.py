from typing import Dict, Any
from app.services.email.base import BaseEmail

class VerificationEmail(BaseEmail):
    @property
    def template_name(self) -> str:
        return "emails/verification.html"
    
    @property
    def subject(self) -> str:
        return "Verify Your Email Address"
    
    def get_context(self, **kwargs) -> Dict[str, Any]:
        context = super().get_context(**kwargs)
        required_fields = ["first_name", "verification_link"]
        for field in required_fields:
            if field not in kwargs:
                raise ValueError(f"Missing required field for VerificationEmail: {field}")
        return context
