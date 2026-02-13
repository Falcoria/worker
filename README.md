# Worker

Worker is the scan execution component in the [Falcoria](https://github.com/Falcoria/falcoria) distributed scanning system. It pulls tasks from the queue and runs Nmap scans. Results go straight to ScanLedger via API.

Each scan has up to two phases: port discovery first, then service detection against the discovered open ports (if enabled in the scan config). Workers don't coordinate with each other — the queue handles task assignment, ScanLedger handles merging.

Adding workers scales throughput linearly. Deploy them on separate machines — cloud VMs, VPSes, VPN endpoints — each with its own network path and IP.

## Quick start

The fastest way to run everything (ScanLedger + Tasker + Worker + Postgres + Redis + RabbitMQ):

```bash
git clone https://github.com/Falcoria/falcoria.git
cd falcoria
./quickstart.sh
```

See the [all-in-one repo](https://github.com/Falcoria/falcoria) for details.

## Standalone setup

For distributed deployments where workers run on separate machines:

```bash
git clone https://github.com/Falcoria/worker.git
cd worker
cp .env.example .env  # edit connection settings
```

### Docker

```bash
docker build -t falcoria-worker .
docker run --env-file .env falcoria-worker
```

### Manual (development)

```bash
sudo apt-get install -y nmap supervisor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
supervisord -c supervisord.conf
```

## Configuration

Environment variables in `.env`:

- RabbitMQ connection (where tasks come from)
- Redis connection (task tracking and locking)
- ScanLedger URL and token (where results are sent)
- Logging level

See `app/config.py` for all options.

## How it works

Worker uses Celery with RabbitMQ for task consumption. Internally:

- **nmap_scan_queue** — receives scan tasks
- **nmap_cancel_queue** — receives cancel requests
- **worker_service_broadcast** — receives broadcast messages (IP registration)

Running tasks and process IDs are tracked in Redis. On completion or cancellation, state is cleaned up and results are uploaded to ScanLedger.

## Documentation

Full documentation: [https://falcoria.github.io/falcoria-docs/](https://falcoria.github.io/falcoria-docs/)

- [Architecture](https://falcoria.github.io/falcoria-docs/architecture/) — how Workers fit into the system
- [Distribution](https://falcoria.github.io/falcoria-docs/concepts/distribution/) — distributed scanning model
- [Scan Configs](https://falcoria.github.io/falcoria-docs/concepts/scan-configs/) — two-phase scanning and config structure

## License

MIT
