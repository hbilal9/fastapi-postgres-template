lint:
	uv run ruff check ./app

format:
	uv run ruff format ./app

start:
	uv run uvicorn app.main:app --reload

alembic-revision:
	uv run alembic revision --autogenerate -m "$(MSG)"

alembic-upgrade:
	uv run alembic upgrade head
