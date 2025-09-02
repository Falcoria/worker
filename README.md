
# Falcoria Worker

Falcoria Worker is the execution agent in the Falcoria system. It receives scan tasks, performs secure Nmap scans, tracks results in Redis, and uploads findings to ScanLedger. Designed for distributed, scalable network scanning with robust task management.

## Architecture & Main Components

- **Celery**: Handles distributed task queueing and execution. Tasks are defined in `app/tasks.py` and routed via custom queues.
- **Redis**: Used for task tracking, locking, and metadata storage. See `app/redis_client.py` and `app/runtime/redis_wrappers.py`.
- **Nmap**: Scans are executed in two phases (open ports, then service scan) via `app/runtime/nmap_runner.py`.
- **ScanLedger Connector**: Uploads scan results to backend via HTTP (`app/runtime/scanledger_connector.py`).
- **Supervisor**: Manages worker processes (see `supervisord.conf`).
- **Docker**: Containerized deployment (see `Dockerfile`).

## Features

- Receives validated scan/cancel tasks via Celery queues
- Executes Nmap scans securely with config-driven options
- Two-phase scan: open ports, then service enrichment
- Tracks running tasks and process IDs in Redis
- Cleans up Redis state after task completion/cancellation
- Uploads results to ScanLedger backend
- Registers worker IP for service discovery
- Configurable via environment variables and `.env` file

## Installation

### Prerequisites

- Python 3.13+
- Docker (recommended) or direct Python environment
- Redis server
- RabbitMQ server

### Build & Run (Docker)

```bash
docker build -t falcoria-worker .
docker run --env-file .env -p 6379:6379 falcoria-worker
```

### Manual Setup

1. Install system dependencies:

    ```bash
    sudo apt-get update && sudo apt-get install -y nmap gcc supervisor git
    ```

2. Install Python dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Configure environment variables in `.env` (see `app/config.py` for options).

4. Start Supervisor:

    ```bash
    supervisord -c supervisord.conf
    ```

## Configuration

All settings are managed via environment variables and `.env` file. See `app/config.py` for available options:

- RabbitMQ connection
- Redis connection
- ScanLedger backend URL/token
- Nmap scan options
- Logging level

## Usage

Worker runs as a persistent background service, processing tasks in real-time. It connects to ScanLedger and Tasker via configured endpoints. Main entrypoint is managed by Supervisor or Docker.

### Task Queues

- **nmap_scan_queue**: Receives scan tasks
- **nmap_cancel_queue**: Receives cancel requests
- **worker_service_broadcast**: Receives broadcast tasks (e.g., IP update)

### Main Tasks

- `scan_task`: Runs Nmap scan, tracks in Redis, uploads results
- `cancel_task`: Cancels running scan by task ID
- `update_worker_ip_task`: Registers worker IP in Redis

## Development

- Code is organized under `app/` and `app/runtime/`
- Extend tasks in `app/tasks.py`
- Add scan logic in `app/runtime/nmap_runner.py`
- Redis wrappers in `app/runtime/redis_wrappers.py`
- Logging via `app/logger.py`

## License

MIT
