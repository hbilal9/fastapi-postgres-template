from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
import datetime

from fastapi import BackgroundTasks

from app.services.email.email_service import email_service
from app.services.email.templates import render_template


class BaseEmail(ABC):
    def __init__(self):
        self.current_year = datetime.datetime.now().year
        self.common_context = {"current_year": self.current_year}
    
    @property
    @abstractmethod
    def template_name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def subject(self) -> str:
        pass
    
    def get_context(self, **kwargs) -> Dict[str, Any]:
        context = self.common_context.copy()
        context.update(kwargs)
        return context
    
    def render_email(self, **kwargs) -> str:
        context = self.get_context(**kwargs)
        return render_template(self.template_name, **context)
    
    async def send(
        self, 
        email_to: str, 
        background_tasks: Optional[BackgroundTasks] = None, 
        **kwargs
    ) -> Union[bool, None]:
        html_content = self.render_email(**kwargs)
        if background_tasks:
            background_tasks.add_task(
                email_service.send_email,
                email_to=email_to,
                subject=self.subject,
                html_content=html_content,
            )
            return None
        else:
            return await email_service.send_email(
                email_to=email_to,
                subject=self.subject,
                html_content=html_content,
            )