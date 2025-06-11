# FastAPI Postgres Template

This is a template project for a FastAPI application with a PostgreSQL database, pgAdmin for database management, and Traefik as a reverse proxy. All services are containerized using Docker.

## Prerequisites

*   Docker and Docker Compose installed.
*   A code editor (e.g., VS Code).
*   A terminal or command prompt.

## Basic Configuration

1.  **Environment Variables**:
    This project uses a `.env` file for local development configuration. If it doesn't exist, create one in the project root by copying `.env.example` (if you have one) or by creating it manually.
    Key variables to check/set in your `.env` file (though many are also set directly in `docker-compose.yml` for Dockerized environment):

    ```env
    # .env
    APP_NAME='FASTAPI Postgres Template'
    FRONTEND_URL='http://localhost:3000' # If you have a frontend

    SECRET_KEY='your_32_char_strong_secret_key_here' # Important: Change this for production
    DEBUG=True # Set to False for production

    # These are used by the application if not overridden by docker-compose environment
    DATABASE_URL="postgresql+psycopg2://hbky:password@db:5432/fastapi_db"
    ALGORITHM='HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES=10080 # 7 days

    # Email settings (optional, configure if needed)
    SMTP_PORT=587
    SMTP_HOST='smtp.example.com'
    SMTP_USER='user@example.com'
    SMTP_PASSWORD='your_smtp_password'
    EMAILS_FROM_EMAIL='noreply@example.com'
    EMAILS_FROM_NAME='Your App Name'
    ```
    **Note**: For the Docker setup, database connection details (`DATABASE_URL`, `DATABASE_USER`, `DATABASE_PASSWORD`, etc.) are primarily sourced from the `environment` section of the `fastapi` and `db` services in the `docker-compose.yml` file. The `DATABASE_URL` in `.env` might be used if your application reads it directly for other purposes or for local non-Docker development.

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
    *   Directly: `http://localhost:5050`
    *   **Login Credentials** (defined in `docker-compose.yml`):
        *   Email: `admin@admin.com`
        *   Password: `admin`

*   **Traefik Dashboard** (for inspecting routes and services):
    *   `http://localhost:8080`

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
    *   **Username**: `hbky` (This is the `POSTGRES_USER` value).
    *   **Password**: `password` (This is the `POSTGRES_PASSWORD` value).
    *   You can leave other settings as default or adjust as needed.
5.  Click **Save**.

Your database server should now appear in the list, and you can browse its contents, run queries, etc.

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

## Further Development

*   Modify API endpoints in `app/api/`.
*   Update database models in `app/models/` and Pydantic schemas in `app/schemas/`.
*   Run database migrations using Alembic if you change your models:
    ```bash
    # Inside the fastapi container or with docker compose exec
    docker compose exec fastapi alembic revision -m "your_migration_message"
    docker compose exec fastapi alembic upgrade head
    ```

Happy coding!
```<!-- filepath: /Users/hbilalkhan/Workspace/Texagon/fastapi-postgres-template/README.md -->
# FastAPI Postgres Template

This is a template project for a FastAPI application with a PostgreSQL database, pgAdmin for database management, and Traefik as a reverse proxy. All services are containerized using Docker.

## Prerequisites

*   Docker and Docker Compose installed.
*   A code editor (e.g., VS Code).
*   A terminal or command prompt.

## Basic Configuration

1.  **Environment Variables**:
    This project uses a `.env` file for local development configuration. If it doesn't exist, create one in the project root by copying `.env.example` (if you have one) or by creating it manually.
    Key variables to check/set in your `.env` file (though many are also set directly in `docker-compose.yml` for Dockerized environment):

    ```env
    # .env
    APP_NAME='FASTAPI Postgres Template'
    FRONTEND_URL='http://localhost:3000' # If you have a frontend

    SECRET_KEY='your_strong_secret_key_here' # Important: Change this for production
    DEBUG=True # Set to False for production

    # These are used by the application if not overridden by docker-compose environment
    DATABASE_URL="postgresql+psycopg2://hbky:password@db:5432/fastapi_db"
    ALGORITHM='HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES=10080 # 7 days

    # Email settings (optional, configure if needed)
    SMTP_PORT=587
    SMTP_HOST='smtp.example.com'
    SMTP_USER='user@example.com'
    SMTP_PASSWORD='your_smtp_password'
    EMAILS_FROM_EMAIL='noreply@example.com'
    EMAILS_FROM_NAME='Your App Name'
    ```
    **Note**: For the Docker setup, database connection details (`DATABASE_URL`, `DATABASE_USER`, `DATABASE_PASSWORD`, etc.) are primarily sourced from the `environment` section of the `fastapi` and `db` services in the `docker-compose.yml` file. The `DATABASE_URL` in `.env` might be used if your application reads it directly for other purposes or for local non-Docker development.

2.  **(Optional) Hosts File Configuration for Traefik:**
    To use the friendly URLs provided by Traefik (e.g., `http://api.localhost`, `http://pgadmin.localhost`), add the following lines to your system's hosts file:
    *   On macOS/Linux: `/etc/hosts`
    *   On Windows: `C:\Windows\System32\drivers\etc\hosts`

    ```
    127.0.0.1 api.localhost
    127.0.0.1 pgadmin.localhost
    ```

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
    *   Directly: `http://localhost:5050`
    *   **Login Credentials** (defined in `docker-compose.yml`):
        *   Email: `admin@admin.com`
        *   Password: `admin`

*   **Traefik Dashboard** (for inspecting routes and services):
    *   `http://localhost:8080`

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
    *   **Username**: `hbky` (This is the `POSTGRES_USER` value).
    *   **Password**: `password` (This is the `POSTGRES_PASSWORD` value).
    *   You can leave other settings as default or adjust as needed.
5.  Click **Save**.

Your database server should now appear in the list, and you can browse its contents, run queries, etc.

## Project Structure (Brief Overview)

```
.
├── app/                  # Main application code
│   ├── api/              # API endpoints (routers)
│   ├── commands/         # Custom management commands (e.g., create_admin.py)
│   ├── core/             # Core application logic, settings
│   ├── crud/             # CRUD operations (Create, Read, Update, Delete)
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

## Further Development

*   Modify API endpoints in `app/api/`.
*   Update database models in `app/models/` and Pydantic schemas in `app/schemas/`.
*   Run database migrations using Alembic if you change your models:
    ```bash
    # Inside the fastapi container or with docker compose exec
    docker compose exec fastapi alembic revision -m "your_migration_message"
    docker compose exec fastapi alembic upgrade head
    ```

Happy coding!
