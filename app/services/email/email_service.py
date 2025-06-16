import logging
import smtplib
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.utils.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    async def send_email(
        self,
        email_to: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> bool:
        if not all(
            [
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                settings.SMTP_USER,
                settings.SMTP_PASSWORD,
                settings.EMAILS_FROM_EMAIL,
            ]
        ):
            logger.error("Email settings not configured")
            return False

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
        message["To"] = email_to

        if text_content is None:
            text_content = html_content.replace("<br>", "\n").replace("</p>", "\n</p>")
            text_content = re.sub(r"<[^>]*>", "", text_content)

        part1 = MIMEText(text_content, "plain")
        part2 = MIMEText(html_content, "html")
        message.attach(part1)
        message.attach(part2)

        try:
            if not settings.SMTP_HOST or not settings.SMTP_PORT:
                raise ValueError("SMTP_HOST and SMTP_PORT must be set")

            server = smtplib.SMTP(str(settings.SMTP_HOST), int(settings.SMTP_PORT))
            if settings.SMTP_TLS:
                server.starttls()

            if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
                raise ValueError("SMTP_USER and SMTP_PASSWORD must be set")
            server.login(str(settings.SMTP_USER), str(settings.SMTP_PASSWORD))

            if not settings.EMAILS_FROM_EMAIL:
                raise ValueError("EMAILS_FROM_EMAIL must be set")
            print(server.sendmail(str(settings.EMAILS_FROM_EMAIL), email_to, message.as_string()))
            server.quit()

            logger.info(f"Email sent successfully to {email_to}")
            return True

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return False
# Singleton instance of the email service for use across the application --> Intentional by @mtalhazulf
email_service = EmailService()