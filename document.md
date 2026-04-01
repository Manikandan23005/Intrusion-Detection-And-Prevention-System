# Intrusion Detection and Prevention System (IDS/IPS) Documentation

This is a comprehensive, detailed breakdown of the Intrusion Detection and Prevention System (IDS/IPS) project. It covers all individual components, from the technology stack used to the overall architecture, right down to the specific workflows of each feature.

---

## 1. Technology Stack & Packages Used

The application is built using a lightweight, practical, and highly capable stack suitable for an on-premise or cloud IDS monitoring deployment.

### Backend Context
* **Python 3.10+**: The core language used across the board. It is selected due to its excellent operating system integration scripting, threading models, and rich ecosystem.
* **Flask (3.0.0)**: Used to build the Central Dashboard and the REST API. Flask is extremely lightweight and optimal for serving the web interface, rendering basic templates, and serving JSON APIs without the overhead of bulkier frameworks.
* **SQLite3**: A serverless, local relational database. Used to store Users, Logs, Settings, IPS Events, and pending Agent Commands. Its lightweight nature is perfect for a standalone network monitoring application where ease of deployment is the focus.
* **Werkzeug Security**: A Flask utility used for password hashing (`generate_password_hash`, `check_password_hash`) to ensure user credentials are safe in the database. 
* **SMTP (smtplib / email.mime)**: Python's built-in libraries used to build and dispatch customized HTML email alerts (via Gmail's SMTP servers) whenever the system detects high-severity events.

### Client/Agent Context (`ids_agent.py`)
* **Watchdog (3.0.0)**: Used for high-performance File System Monitoring. Instead of continuously polling (which wastes CPU), `watchdog` hooks into OS-level events (like `inotify` in Linux) to register instantaneous file creation or modification events on critical directories (like `/etc`).
* **Requests (2.31.0)**: Used by the monitoring agents to dispatch HTTP POST telemetry (to `/api/v1/alerts`) and poll HTTP GET requests (checking for admin commands via `/api/v1/commands`).
* **Subprocess & OS**: Fundamental Python modules used aggressively by the Agent to directly interface with Unix tooling: `journalctl` (auth logs), `iptables` (firewall blocking), `ps` (process listings), and `kill` (terminating malicious apps).
* **Threading**: The agent leverages the `threading` module to gracefully run four distinct monitoring tasks continuously in parallel without blocking each other.

### Deployment Context
* **Docker & Docker Compose**: The server runs containerized. Notably, it utilizes `network_mode: "host"` and `privileged: true`. This is a critical design choice because the dashboard needs the ability to instruct the OS firewall (`iptables`) and read deep host mounts like `/var/log/journal` without Docker's isolated network bridging getting in the way.

---

## 2. Total Architecture Overview

The system operates on a **Hub-and-Spoke (Server-Agent) Architecture**. 

1. **Central Server Node (The Hub)**: This is your Flask application (`web_ids/app.py`). It acts as a centralized dashboard. It exposes Web UIs for human administrators and a REST API for programmatic agents. It holds the "master state" in `ids.db`.
2. **Endpoint Agents (The Spokes)**: The `ids_agent.py` script. This is deployed to endpoints, Linux VMs, or physical hosts tracking its own environment. It requires the Central Server URL and an API Key (provided by the dashboard).

### The Communication Flow:
* **Push (Telemetry)**: The Agent identifies suspicious things, creates JSON packages, and HTTP POSTs them to the Central Server.
* **Poll (Commands)**: Since the Central Server usually can't reach inside local networks or firewalls directly to contact the agent, the Agent acts as a Poller—asking the Central Server every 5 seconds "Do you have any new IPS commands for me to execute?"

---

## 3. Detailed Workflow of Each Functionality

Each capability of the system solves a specific security challenge:

### A. File Integrity Monitoring (FIM)
* **Goal**: Detect if critical system configurations (e.g., config files inside `/etc`) are being tampered with.
* **Workflow**: The agent initiates an `Observer` via the `watchdog` library on the target directory. If `on_modified` or `on_created` events hit, they are analyzed. It ignores temporary files (`.swp`, `.tmp`, db journals). It implements a 10-second debounce mechanism to prevent event flooding. If valid, an HTTP POST sends a `low` severity alert ("File Modification") to the Central Server database.

### B. Authentication & Brute-Force Monitoring
* **Goal**: Detect unauthorized access and brute-force SSH attacks in real-time.
* **Workflow**: The agent runs `subprocess.Popen` securely tailing Linux auth logs using `journalctl -f -n 0`. It yields incoming lines instantly and feeds them to parsers utilizing Regular Expressions (`re`). 
    * It categorizes specific events: "Accepted password", "Failed password", "sudo execution", and "root session opened".
    * **Intrusion Prevention (IPS) Execution**: If it calculates > 3 back-to-back SSH failed passwords from the same IP, it triggers an OS-level lock-out: It executes a `subprocess` to inject an `sudo iptables -A INPUT -s [IP] -j DROP` rule to block the attacker immediately for 60 seconds. Finally, it sends a `high` severity alert.

### C. Malicious Process Profiling
* **Goal**: Identify running malware, crypto-miners, or hacker enumeration tools.
* **Workflow**: A thread loops every 5 seconds running `ps -eo pid,user,comm`. It correlates the running processes against a list of known malicious tools (e.g., `nmap`, `netcat`, `sqlmap`, `metasploit`, `cgminer`). 
    * If a match occurs, it flags an Alert. 
    * **IPS Execution**: It immediately attempts to execute `sudo kill -9 <PID>` to terminate the malware aggressively, followed by notifying the dashboard (`/api/v1/ips_events`) that an auto-remediation event occurred.

### D. The Admin Dashboard & Remote Command Execution
* **Goal**: A centralized pane of glass to visualize the entire network and manually respond.
* **Workflow**: Administrators log in to the Flask portal, visualizing aggregated telemetry across pages (`/`, `/processes`, `/ips`). If the Administrator clicks "Block IP" or "Kill Process", the Flask app doesn't attempt to SSH into a machine. Instead, it securely queues the intention into the `agent_commands` table with a `pending` status.
* **The Agent Poller**: Every 5 seconds, the Agent pulls its command list via GET `/api/v1/commands`. If it sees "Block IP X", it executes the local `iptables` drop rule locally, and then POSTs back to `/api/v1/commands/<CMD_ID>/complete` to resolve the task, completely asynchronous and secure.

### E. Alert Dispatch & SMTP Relays
* **Goal**: Ensure the user knows a breach happens even if not looking at the dashboard.
* **Workflow**: During telemetry ingest at `/api/v1/alerts`, if the endpoint receives a JSON payload identifying as `medium` or `high` severity, and the admin has `monitoring_active` set to true, it triggers `core.alert.send_email`. This fetches the saved App Password from settings, constructs a formatted HTML email containing the attacker's IP and Context, and pushes it through the `smtp.gmail.com` relay.

---

## Summary

This project behaves like an enterprise cybersecurity platform (e.g., Splunk + CrowdStrike) simplified. By offloading complex file/process monitoring securely down to the target Linux machines via `ids_agent.py`, the `web_ids` Server stays incredibly lightweight and only handles display, storage, and message routing.
