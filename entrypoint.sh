#!/bin/sh
uv run alembic upgrade head
uv run python -m app.commands.create_admin
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
