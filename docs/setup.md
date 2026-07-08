# Setup and Configuration

This document provides instructions for setting up the Sentinel SOA environment, configuring services via environment variables, and seeding the database with initial data.

## 1. Quick Start

The entire environment is orchestrated with Docker Compose. To get started:

1.  **Create an environment file:** Copy the example file to `.env`. This file will hold all your local configuration secrets and settings.
    ```bash
    cp .env.example .env
    ```

2.  **Edit `.env`:** Open the `.env` file and at a minimum, provide your API key for the desired LLM provider (e.g., `GEMINI_API_KEY` for Google Gemini).

3.  **Build and run the services:**
    ```bash
    docker-compose up --build
    ```
    This command builds the images for all services and starts them. The frontend will be available at `http://localhost:3000` and the core API at `http://localhost:8000`.

## 2. Data Seeding

After the containers are running, you need to seed the database with initial users, telemetry clients, and heuristic rules. This is done using the `bootstrap_local_data.py` script.

1.  **Execute the script:** Run the script from the root of the project.
    ```bash
    python scripts/bootstrap_local_data.py
    ```

2.  **Script Options:**
    *   `--users-seed <path>`: Path to the JSON file for user seeding. (Default: `data/users_seed.json`)
    *   `--clients-seed <path>`: Path to the JSON file for telemetry client seeding. (Default: `data/telemetry_clients_seed.json`)
    *   `--overwrite-existing`: Use this flag to update existing users and clients if they are found in the database. By default, existing entries are skipped.
    *   `--force-rules`: Use this flag to clear all existing heuristic rules, versions, and audit logs before seeding them from `data/mongodb/heuristic_rules.json`. **Use with caution.**

## 3. Environment Variables

Configuration is managed via environment variables defined in the `.env` file and loaded by Docker Compose.

### LLM Provider Selection

These variables control which Language Model provider the `mcp_server` uses for analysis.

| Variable | Description | Options | Default |
|---|---|---|---|
| `LLM_PROVIDER` | Selects the primary LLM provider. | `gemini`, `ollama` | `gemini` |
| `GEMINI_API_KEY` | Your Google Gemini API Key. Required if `LLM_PROVIDER=gemini`. | - | - |
| `GEMINI_MODEL` | The specific Gemini model to use. | `gemini-1.5-flash`, `gemini-1.5-pro` | `gemini-1.5-flash` |
| `OLLAMA_BASE_URL` | The base URL where the Ollama service is running. | - | `http://localhost:11434` |
| `OLLAMA_MODEL` | The local Ollama model to use. You must pull this model first. | `mistral`, `llama2`, etc. | `mistral` |
| `OLLAMA_TIMEOUT_SECONDS` | Timeout for requests to Ollama. Increase for larger models. | - | `300` |

### Core Orchestrator Settings

These variables configure the main `core` service.

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET_KEY` | A long, random, and secret string used for signing JWTs. | `your-super-secret-key-here` |
| `WINDOW_THRESHOLD_REQUESTS` | Number of requests from a source IP within the time window to trigger an alert. | (Set in `.env`) |
| `WINDOW_DURATION_SECONDS` | Duration of the sliding time window for correlating requests. | (Set in `.env`) |
| `MAX_ALERTS_IN_MEMORY` | Maximum number of alerts to keep in the in-memory queue. | (Set in `.env`) |
| `BOOTSTRAP_ON_STARTUP` | If `true`, runs the data seeding process when the container starts. | `true` |
| `MCP_SERVER_HOST` | Hostname of the MCP server, as seen from the core service. | `mcp_server` |
| `MCP_SERVER_PORT` | Port of the MCP server. | `8080` |

### Database & Cache Settings

| Variable | Description | Default |
|---|---|---|
| `MONGO_HOST` | Hostname for the MongoDB service. | (Set in `.env`) |
| `MONGO_PORT` | Port for the MongoDB service. | (Set in `.env`) |
| `MONGO_USER` | Username for MongoDB authentication. | (Set in `.env`) |
| `MONGO_PASSWORD` | Password for MongoDB authentication. | (Set in `.env`) |
| `MONGO_DB_NAME` | The name of the main application database in MongoDB. | (Set in `.env`) |
| `RULES_MONGO_DB_NAME` | The name of the database for heuristic rules. | `heuristy` |
| `REDIS_HOST` | Hostname for the Redis service. | (Set in `.env`) |
| `REDIS_PORT` | Port for the Redis service. | (Set in `.env`) |
| `REDIS_PASSWORD` | Password for Redis authentication. | (Set in `.env`) |

### Victim & Telemetry Settings

These variables configure the `victim_app` and the `log_shipper` (Vector).

| Variable | Description | Default |
|---|---|---|
| `VICTIM_SOURCE_ID` | A unique identifier for the monitored application instance. | `victim-app-01` |
| `TELEMETRY_FORWARD_URL` | The full URL where the log shipper sends telemetry batches. | `http://core:8000/api/v1/telemetry/ingest/batch` |
| `TELEMETRY_HMAC_PUBLIC_KEY`| The public key (Client ID) used by the core to look up the shared secret for HMAC signature verification. | `victim-app-01` |
| `TELEMETRY_HMAC_SECRET` | The shared secret key used by the `victim_app` to sign telemetry payloads. Must match the secret stored in the database for the corresponding client. | (A default is provided) |

## 4. Local Ollama Setup

To run the system with a local LLM and avoid external API calls:

1.  **Run Ollama Container:** The included `docker-compose.yml` already defines an `ollama` service.

2.  **Pull a Model:** From your host machine, `exec` into the running `ollama` container and pull a model. `mistral` is recommended as a starting point.
    ```bash
    docker exec -it sentinel_ollama ollama pull mistral
    ```

3.  **Configure `.env`:** Change the `LLM_PROVIDER` in your `.env` file.
    ```
    LLM_PROVIDER=ollama
    ```

4.  **Restart the MCP Server:** To apply the change, restart the `mcp_server` container.
    ```bash
    docker-compose restart mcp_server
    ```
