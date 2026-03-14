# Intrusion Detection System (Dockerized)

This project has been transformed into a fully deployable setup using Docker and Poetry.

## Architecture
- **Server**: A Flask-based API (`api.py`) running on Port 5000 and a Dashboard (`dashboard.py`) running on Port 8080.
- **Client**: An intrusion detection agent that monitors the file system and SSH authorization logs using `journalctl`.

## Prerequisites
- Docker
- Docker Compose

## Quickstart

To build and run the system, simply run the following command in the root project directory:
```bash
docker compose up -d --build
```

### Accessing the Dashboard

Once the containers are up and running, you can access the dashboard interface via:
http://localhost:8080

### Checking the API

The API used by the clients to report intrusion logs is available on:
http://localhost:5000

## Configuration
The `client` reads configurations from `client/config.json`.
In the docker-compose setup, the `server` logs are preserved in a volume, and the `client` uses the host's networking mode and mounts the host's `/var/log/journal` to properly analyze SSH login logs.

**Important**: 
- If you intend to use the automatic IP blocking functionality inside the client container, it operates dynamically based on host network monitoring and iptables. The docker-compose configuration grants the client `privileged: true` permissions and `network_mode: "host"` so it can execute this action effectively.
- Make sure `config.json` is properly populated with your target `notification_email`.

## Poetry Dependency Management
The project utilizes `Poetry` internally to manage dependencies for both the client and server components in a pristine way within their respective Docker containers.

If you ever need to develop locally or rebuild `poetry.lock`:
1. Navigate to the respective folder (`client` or `server`).
2. Run `poetry install`.
