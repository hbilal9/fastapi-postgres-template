from app.services.email.base import BaseEmail


class NotificationEmail(BaseEmail):
    def __init__(self, subject: str = None, template_name: str = None):
        super().__init__()
        self._subject = subject
        self._template_name = template_name

    @property
    def template_name(self) -> str:
        return self._template_name or "emails/notification.html"

    @property
    def subject(self) -> str:
        return self._subject or "Notification"
