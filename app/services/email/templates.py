from pathlib import Path

from fastapi.templating import Jinja2Templates

templates_dir = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def render_template(template_name: str, **kwargs) -> str:
    template = templates.get_template(template_name)
    return template.render(**kwargs)
