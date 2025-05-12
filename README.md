# Worker

Worker is the execution agent in the Falcoryon system. It receives scan tasks from Tasker and performs Nmap scans, then stores results in ScanLedger via HTTP.

## Features

- Receives validated scan tasks via dedicated queue or API.
- Executes Nmap scans securely with config-driven options.
- Filters and stores only open ports for each IP.
- Supports incremental import modes: insert, update, replace.
- Sends results to ScanLedger and notifies Tasker on phase completion.
- Can be extended for multi-phase chaining (e.g., ports → services).

## Usage

Worker runs as a persistent background service (via Supervisor or Docker) and processes tasks in real-time. It connects to ScanLedger and Tasker via environment-configured HTTP endpoints.

## License

MIT
