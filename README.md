# FastAPI Postgres Template

This is a template project for a FastAPI application with a PostgreSQL database, pgAdmin for database management, and Traefik as a reverse proxy. All services are containerized using Docker.

## Prerequisites

*   Docker and Docker Compose installed.
*   A code editor (e.g., VS Code).
*   A terminal or command prompt.

## Basic Configuration

1.  **Environment Variables**:
    This project uses a `.env` file for local development configuration. If it doesn't exist, run this command to create

    ```
    cp .env.example .env
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
    *   Directly: `http://localhost:9000`
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

Happy coding!
