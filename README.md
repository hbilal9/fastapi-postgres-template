# FastAPI Postgres Template

This is a template project for a FastAPI application with a PostgreSQL database, pgAdmin for database management, and Traefik as a reverse proxy. All services are containerized using Docker.

## Features

- **FastAPI Backend**: High-performance API framework
- **PostgreSQL Database**: Robust relational database
- **Alembic Migrations**: Database versioning and migrations
- **Docker & Docker Compose**: Containerization for consistent environments
- **pgAdmin**: Database management UI
- **Traefik**: API Gateway and reverse proxy
- **Authentication**:
  - JWT Token-based authentication (Bearer tokens)
  - Cookie-based authentication with HTTP-only cookies
  - Refresh token functionality
  - Password reset functionality
- **Environment-based configuration**: Different settings for development, staging, and production

## Prerequisites

- **Local Development**:
  - Python 3.11 or higher
  - PostgreSQL installed locally or accessible
  - pip or another Python package manager

- **Docker Deployment**:
  - Docker and Docker Compose installed
  - A code editor (e.g., VS Code)
  - A terminal or command prompt

## Basic Configuration

1.  **Environment Variables**:
    This project uses a `.env` file for local development configuration. If it doesn't exist, run this command to create:

    ```python
    cp .env.example .env
    ```

    Ensure you set the following environment variables in your `.env` file:

```python
# Core settings
FRONTEND_URL='http://localhost:3000'
SECRET_KEY='your_32_char_strong_secret_key_here'
DEBUG=True
ENVIRONMENT='development'  # Options: development, staging, production

# Database settings
POSTGRES_USER="your_username"
POSTGRES_PASSWORD="your_password"
POSTGRES_DB_NAME="fastapi_db"

# Authentication
ALGORITHM='HS256'
ACCESS_TOKEN_EXPIRE_MINUTES=30  # Short-lived access tokens for security
REFRESH_TOKEN_EXPIRE_DAYS=7     # Longer-lived refresh tokens
```

## Local Installation and Setup

#### (Recommended uv)

1. **Install dependencies directly with uv**:

   ```bash
   # uv will make .venv automatically
   uv sync
   ```
2. **Install new dependencies with uv**:

   ```bash
   uv add dependency_name
   ```
3. **Run server**:

   ```bash
   uv run uvicorn app.main:app --reload
   ```

#### (Not recommended)

1. **Create a virtual environment**:

   ```bash
   # Using standard venv
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # OR using uv (faster)
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies**:

   ```bash
   # Using pip
   pip install -r requirements.txt

   # OR using uv (faster)
   uv pip install -r requirements.txt
   ```


#### Set up the database:

   Create your PostgreSQL database and run migrations:

   ```bash
   # Make sure you've set the correct DATABASE_URL in your .env file
   alembic upgrade head
   ```

### Database Migrations Guide

This project uses Alembic for managing database schema migrations. Understanding the migration workflow is essential for all developers working on this project.

#### How Migrations Work

1. **Migration Tracking:**
   - Alembic maintains a version table (`alembic_version`) in your database
   - This table stores the current revision ID that has been applied
   - Each migration has a unique revision ID (e.g., `9ead825737b6`)

2. **Creating New Migrations:**

   When you modify SQLAlchemy models (e.g., add/change/remove columns), you need to create and apply migrations:

   ```bash
   # Generate a migration automatically by detecting model changes
   alembic revision --autogenerate -m "describe_your_changes"

   # Review the generated migration file in app/alembic/versions/
   # Make any necessary adjustments (e.g., adding default values for non-nullable columns)

   # Apply the migration
   alembic upgrade head
   ```

3. **Common Migration Tasks:**

   ```bash
   # View current migration status
   alembic current

   # View migration history
   alembic history

   # Downgrade to a specific version
   alembic downgrade <revision_id>

   # Downgrade one version
   alembic downgrade -1
   ```

4. **Important Considerations:**

   - **Adding Non-Nullable Columns:** When adding non-nullable columns to existing tables, you MUST provide a server_default value
   - **JSONB Columns:** Require the PostgreSQL dialect to be properly imported and used
   - **Data Migrations:** For complex data transformations, you may need to write custom Python in your migration scripts
   - **Testing Migrations:** Always test migrations in a development environment before applying to production

5. **Troubleshooting Migration Issues:**

   - If a migration fails, check the error message carefully - common issues include constraint violations or missing dependencies
   - If you need to reset a failed migration, you may need to modify the `alembic_version` table directly
   - When working with existing data, consider data integrity and constraints

4. **Run the application**:

   ```bash
   uvicorn app.main:app --reload
   ```

   The API will be available at http://localhost:8000

## Docker Build and Run

To build and start all the services (FastAPI application, PostgreSQL database, pgAdmin, and Traefik):

```bash
docker compose up --build -d
```

*   `--build`: Forces Docker to rebuild the images if there are changes (e.g., in your `Dockerfile` or application code).
*   `-d`: Runs the containers in detached mode (in the background).

To stop the services:

```bash
docker compose down
```

To stop and remove volumes (useful for a clean restart, **will delete database data**):

```bash
docker compose down -v
```

To view logs for all services:
```bash
docker compose logs -f
```
To view logs for a specific service (e.g., `fastapi`):
```bash
docker compose logs -f fastapi
```

## Accessing Services

Once the containers are running:

*   **Backend API (FastAPI)**:
    *   Via Traefik: `http://api.localhost`
    *   Directly (if Traefik is not used or for direct port access): `http://localhost:8000`
    *   API Docs (Swagger UI): `http://api.localhost/docs` or `http://localhost:8000/docs`
    *   Alternative API Docs (ReDoc): `http://api.localhost/redoc` or `http://localhost:8000/redoc`

*   **pgAdmin (Database Management)**:
    *   Via Traefik: `http://pgadmin.localhost`
    *   Directly: `http://localhost:9000`
    *   **Login Credentials** (defined in `docker-compose.yml`):
        *   Email: `admin@admin.com`
        *   Password: `admin`

*   **Traefik Dashboard** (for inspecting routes and services):
    *   `http://localhost:8080`

## Authentication

This application supports two authentication methods:

### 1. Bearer Token Authentication (Standard OAuth2)

- **Login**: Send a POST request to `/api/auth/token` with username/password to get an access token
- **Usage**: Include the token in the Authorization header: `Authorization: Bearer <your_token>`
- **API Docs**: Works with Swagger UI's "Authorize" button

### 2. Cookie-Based Authentication

- **Login**: Send a POST request to `/api/auth/login` with username/password
- **Security**: Tokens are stored in HTTP-only cookies for protection against XSS attacks
- **Refresh**: When the access token expires, use `/api/auth/refresh` to get a new one
- **Logout**: Send a POST request to `/api/auth/logout` to clear authentication cookies

### Environment-Based Security

Cookie security settings are automatically configured based on the `ENVIRONMENT` variable:

- **Development**: Less restrictive settings (HTTP allowed, lax same-site policy)
- **Staging**: HTTPS required, lax same-site policy
- **Production**: HTTPS required, strict same-site policy

## pgAdmin: Connecting to the PostgreSQL Database

After logging into pgAdmin, you'll need to register your PostgreSQL server (the `db` service from `docker-compose.yml`):

1.  In the pgAdmin browser tree (left panel), right-click on **Servers**.
2.  Select **Register** -> **Server...**.
3.  In the **General** tab:
    *   **Name**: Enter a descriptive name for your server (e.g., `Local Docker DB`, `fastapi_db_service`).
4.  Switch to the **Connection** tab:
    *   **Host name/address**: `db` (This is the service name of your PostgreSQL container in `docker-compose.yml`).
    *   **Port**: `5432` (Default PostgreSQL port).
    *   **Maintenance database**: `fastapi_db` (This is the `POSTGRES_DB` value from your `db` service environment).
    *   **Username**: `texagon` (This is the `POSTGRES_USER` value).
    *   **Password**: `password` (This is the `POSTGRES_PASSWORD` value).
    *   You can leave other settings as default or adjust as needed.
5.  Click **Save**.

Your database server should now appear in the list, and you can browse its contents, run queries, etc.


## Use of Pagination
```python
#service.py
from app.utils.pagination import paginator
@paginator(UserSchema)
async def get_users_service(
    db: Session,
    current_user: CurrentUser,
    start_date: date = None,
    end_date: date = None,
    page: int = 1,
    page_size: int = 10,
):
    query = db.query(UserModel)
    if start_date:
        query = query.filter(UserModel.created_at >= start_date)
    if end_date:
        query = query.filter(UserModel.created_at <= end_date)
    return query


#router.py
from .service import users_service
from app.schema.pagination import PaginationResponseSchema

@router.get(
    "/users",
    response_model=PaginationResponseSchema[UserSchema],
    status_code=status.HTTP_200_OK,
)
async def get_users(
    request: Request,
    current_user: CurrentUser,
    db_session: DbSession,
    start_date: date = None,
    end_date: date = None,
    page: int = 1,
    per_page: int = 10,
):
    users = await get_users_service(
        db_session, current_user, start_date, end_date, page, per_page
    )
    return users

```

## Pre-commit Hooks
This project uses pre-commit to automatically check and format code before each commit.
Pre-commit hooks help enforce code style, catch errors early, and keep your codebase clean.

### Install the hooks
 ```
uv run pre-commit install
 ```
### Update the hooks
 ```
uv run pre-commit autoupdate
 ```
### Run all hooks manually (recommended before your first commit):
```
uv run pre-commit run --all-files
```
### What gets checked?
    Code formatting: black, autopep8, isort
    Linting: flake8, bandit, autoflake
    YAML and whitespace checks
    Security checks: bandit
### Troubleshooting
If you add new hooks or update .pre-commit-config.yaml, run:
```
uv run pre-commit install
uv run pre-commit autoupdate
```
To clear the pre-commit cache (if you see strange errors):
```
uv run pre-commit clean
```



## Project Structure (Brief Overview)

```
.
├── app/                  # Main application code
│   ├── api/              # API endpoints (routers)
│   ├── commands/         # Custom management commands (e.g., create_admin.py)
│   ├── models/           # SQLAlchemy database models
│   ├── schemas/          # Pydantic schemas for data validation and serialization
│   ├── services/         # Business logic services
│   ├── utils/            # Utility functions (e.g., database connection, security)
│   └── main.py           # FastAPI application entry point
├── alembic/              # Alembic database migration scripts
├── tests/                # Unit and integration tests
├── .env                  # Local environment variables (create this file)
├── .gitignore
├── alembic.ini           # Alembic configuration
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile            # Dockerfile for the FastAPI application
├── entrypoint.sh         # Entrypoint script for the FastAPI container
├── init.sql              # SQL script for initial database setup (e.g., creating roles)
├── pyproject.toml        # Project metadata and dependencies (using Poetry/uv)
├── README.md             # This file
└── uv.lock               # Lock file for dependencies managed by uv
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**:
   - Check if PostgreSQL is running
   - Verify your DATABASE_URL in the .env file
   - Ensure your PostgreSQL user has proper permissions

2. **Authentication Issues**:
   - Make sure SECRET_KEY is set correctly
   - Check that COOKIE_SECURE is False in development if not using HTTPS

3. **Alembic Migration Errors**:
   - Run `alembic revision --autogenerate -m "message"` to create a new migration
   - Check your database models for any issues


### Getting Help

If you encounter issues not covered here, please check the FastAPI documentation or create an issue in the repository.

Happy coding!
