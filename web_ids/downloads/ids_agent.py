import time
import subprocess
import re
import argparse
import requests
import threading
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("Please install watchdog: pip install watchdog")
    exit(1)


SERVER_URL = ""
API_KEY = ""

def trigger_alert(alert_type, ip_address, message, severity):
    if not SERVER_URL or not API_KEY:
        print("[WARN] Server URL or API Key is missing. Cannot send alert.")
        return

    cloud_url = f"{SERVER_URL}/api/v1/alerts"
    payload = {
        "api_key": API_KEY,
        "alert_type": alert_type,
        "ip_address": ip_address,
        "message": message,
        "severity": severity
    }
    
    try:

        response = requests.post(cloud_url, json=payload, timeout=10)
        if response.status_code == 201:
            print(f"[OK] Alert sent to cloud: {alert_type} - {message}")
        else:
            print(f"[ERROR] Failed to send alert ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to server: {e}")

def trigger_ips_event(action, target, details):
    if not SERVER_URL or not API_KEY: return
    cloud_url = f"{SERVER_URL}/api/v1/ips_events"
    payload = {
        "api_key": API_KEY,
        "action": action,
        "target": target,
        "details": details
    }
    try:
        response = requests.post(cloud_url, json=payload, timeout=10)
        if response.status_code == 201:
            print(f"[OK] IPS action sent to cloud: {action} on {target}")
        else:
            print(f"[ERROR] Failed to send IPS action to cloud ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to server for IPS action: {e}")

def block_ip(ip_address, duration=60):
    def block_ip_temporarily():
        try:
            if not ip_address or ip_address == "Unknown":
                return

            cmd_add = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                cmd_add.insert(0, "sudo")
            
            subprocess.run(cmd_add, check=True)
            print(f"[INFO] Blocked IP: {ip_address} for {duration} seconds locally.")
            trigger_ips_event("Block IP", ip_address, f"Blocked malicious IP for {duration} seconds.")
            
            time.sleep(duration)

            cmd_del = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                cmd_del.insert(0, "sudo")

            subprocess.run(cmd_del, check=True)
            print(f"[INFO] Unblocked IP: {ip_address} locally.")
            trigger_ips_event("Unblock IP", ip_address, "Automatically unblocked IP after duration expired.")

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] iptables command failed: {e}")

    thread = threading.Thread(target=block_ip_temporarily, daemon=True)
    thread.start()

class IntrusionHandler(FileSystemEventHandler):
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir
        self.recent_events = {}

    def should_ignore(self, path):
        return any(path.endswith(ext) for ext in ['.swp', '.tmp', '~', '.db', '.db-journal'])

    def should_alert(self, path):
        now = time.time()
        last_time = self.recent_events.get(path, 0)
        if now - last_time > 10: 
            self.recent_events[path] = now
            return True
        return False

    def on_modified(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            if self.should_alert(event.src_path):
                trigger_alert("File Modification", "Unknown", f"User modified a file: {event.src_path}", "low")

    def on_created(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            if self.should_alert(event.src_path):
                trigger_alert("File Creation", "Unknown", f"A new file was created: {event.src_path}", "low")

class IntrusionMonitor:
    def __init__(self, path):
        self.event_handler = IntrusionHandler(path)
        self.observer = Observer()
        self.path = path

    def run(self):
        print(f"[INFO] File Monitoring started on {self.path}")
        self.observer.schedule(self.event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except Exception:
            self.observer.stop()
            print("[INFO] Monitoring stopped.")
        self.observer.join()

class AuthLogMonitor:
    f_count = 0
    def __init__(self):
        self.journalctl = subprocess.Popen(
            ['journalctl', '-f', '-n', '0'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    def run(self):
        print("[INFO] Starting journalctl auth monitor...")
        try:
            for line in self.journalctl.stdout:
                self.parse_log(line.strip())
        except Exception as e:
            print(f"Error in auth log monitor: {e}")

    def parse_log(self, log_line):
        if "Accepted password for" in log_line:
            match = re.search(r"Accepted password for (\w+) from ([\d\.]+)", log_line)
            ip = ""
            if match:
                user, ip = match.group(1), match.group(2)
                msg = f"SSH login successful: user '{user}' from {ip}"
            else:
                match = re.search(r"Accepted password for (\w+)", log_line)
                if match:
                    user = match.group(1)
                    msg = f"SSH login successful: user '{user}' (local or IP not found)"
                else:
                    return
            trigger_alert("Login Attempt", ip if ip else "Unknown or Local", msg, "medium")
            return

        if "Failed password for" in log_line:
            ip = ""
            AuthLogMonitor.f_count += 1 
            match = re.search(r"Failed password for (invalid user )?(\w+) from ([\d\.]+)", log_line)
            if match:
                invalid = match.group(1) or ""
                user, ip = match.group(2), match.group(3)
                msg = f"SSH login failed: {invalid.strip()}user '{user}' from {ip}"
            else:
                fallback = re.search(r"Failed password for (invalid user )?(\w+)", log_line)
                if fallback:
                    user = fallback.group(2)
                    msg = f"SSH login failed: user '{user}' (IP not found)"
                else:
                    return

            if AuthLogMonitor.f_count > 3 and ip:
                block_ip(ip, 60)
            
            trigger_alert("Login Failed", ip if ip else "Unknown", msg, "high")
            return

        if "sudo" in log_line and "COMMAND=" in log_line:
            user = re.search(r'^.*sudo\[\d+\]: (\w+)', log_line)
            cmd = re.search(r'COMMAND=(.*)', log_line)
            if user and cmd:
                msg = f"Sudo command executed by {user.group(1)}: {cmd.group(1)}"
                trigger_alert("Privilege Escalation", "Localhost", msg, "medium")
            return

        if "session opened for user root" in log_line:
            user = re.search(r'by (\w+)\(uid=', log_line)
            usrmsg = user.group(1) if user else "Unknown"
            msg = f"Root session opened by {usrmsg}"
            trigger_alert("Root Access", "Localhost", msg, "high")
            return

class ProcessMonitor:
    def __init__(self):
        self.malicious_keywords = ['nmap', 'nc', 'netcat', 'hydra', 'sqlmap', 'john', 'metasploit', 'xmrig', 'cgminer']
        self.reported = set()

    def run(self):
        print("[INFO] Starting Process Monitor...")
        while True:
            try:
                result = subprocess.run(["ps", "-eo", "pid,user,comm"], capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    parts = line.strip().split(None, 2)
                    if len(parts) == 3:
                        pid, user, comm = parts
                        for keyword in self.malicious_keywords:
                            if re.search(rf'\b{keyword}\b', comm.lower()) and pid not in self.reported:
                                trigger_alert("Malicious Process Detected", "Localhost", f"Suspicious process running: {comm} (PID: {pid}, User: {user})", "high")
                                self.reported.add(pid)
                                

                                print(f"[IPS] Killing malicious process {comm} (PID: {pid})")
                                cmd_kill = ["kill", "-9", pid]
                                if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                                    cmd_kill.insert(0, "sudo")
                                try:
                                    subprocess.run(cmd_kill, check=True)
                                    trigger_ips_event("Kill Process", pid, f"Auto-killed malicious process '{comm}'")
                                except Exception as e:
                                    print(f"[ERROR] Failed to kill process {pid}: {e}")
            except Exception as e:
                pass
            time.sleep(5)

class CommandPoller:
    def run(self):
        print("[INFO] Starting server command poller...")
        while True:
            try:
                if SERVER_URL and API_KEY:
                    resp = requests.get(f"{SERVER_URL}/api/v1/commands?api_key={API_KEY}", timeout=10)
                    if resp.status_code == 200:
                        cmds = resp.json().get("commands", [])
                        for cmd in cmds:
                            self.execute_command(cmd)
            except Exception:
                pass
            time.sleep(5)
            
    def execute_command(self, cmd):
        c_id = cmd['id']
        action = cmd['command']
        target = cmd['target']
        print(f"[INFO] Server Command: {action} on {target}")
        try:
            if action == 'unblock_ip':
                cmd_del = ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"]
                if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                    cmd_del.insert(0, "sudo")
                subprocess.run(cmd_del, check=True)
                trigger_ips_event("Unblock IP", target, "Manually unblocked via dashboard.")
            elif action == 'block_ip':
                cmd_add = ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"]
                if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                    cmd_add.insert(0, "sudo")
                subprocess.run(cmd_add, check=True)
                trigger_ips_event("Block IP", target, "Manually blocked via dashboard.")
            elif action == 'kill_process':
                cmd_kill = ["kill", "-9", str(target)]
                if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
                    cmd_kill.insert(0, "sudo")
                subprocess.run(cmd_kill, check=True)
                trigger_ips_event("Kill Process", target, "Manually killed process via dashboard.")
        except Exception as e:
            print(f"[ERROR] Command failed: {e}")
        try:
            requests.post(f"{SERVER_URL}/api/v1/commands/{c_id}/complete", json={"api_key": API_KEY}, timeout=5)
        except:
            pass

def main():
    global SERVER_URL, API_KEY
    parser = argparse.ArgumentParser(description="IDS Agent to monitor system and send alerts.")
    parser.add_argument("--server", required=True, help="URL of the Central IDS Server (e.g. http://192.168.1.10:9090)")
    parser.add_argument("--api-key", required=True, help="Your API Key from the IDS Dashboard")
    parser.add_argument("--watch-dir", default="/etc", help="Directory to monitor for file changes (default /etc)")
    
    args = parser.parse_args()
    SERVER_URL = args.server.rstrip("/")
    API_KEY = args.api_key
    
    print(f"=== Starting Local IDS Agent ===")
    print(f"Target Server: {SERVER_URL}")
    print(f"Monitoring Directory: {args.watch_dir}")
    print("Press Ctrl+C to stop.")
    
    auth_monitor = AuthLogMonitor()
    threading.Thread(target=auth_monitor.run, daemon=True).start()

    proc_monitor = ProcessMonitor()
    threading.Thread(target=proc_monitor.run, daemon=True).start()

    cmd_poller = CommandPoller()
    threading.Thread(target=cmd_poller.run, daemon=True).start()

    file_monitor = IntrusionMonitor(path=args.watch_dir)
    threading.Thread(target=file_monitor.run, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Agent stopped by user.")

if __name__ == "__main__":
    main()
