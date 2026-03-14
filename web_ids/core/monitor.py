import time
import subprocess
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.alert import trigger_alert, block_ip

class IntrusionHandler(FileSystemEventHandler):
    def __init__(self):
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
        self.event_handler = IntrusionHandler()
        self.observer = Observer()
        self.path = path

    def run(self):
        print(f"[INFO] File Monitoring started on {self.path}")
        self.observer.schedule(self.event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
            print("[INFO] Monitoring stopped by user.")
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
        for line in self.journalctl.stdout:
            self.parse_log(line.strip())

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
                block_ip(ip, 60) # Block for 60 seconds
            
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
        
        if "adduser" in log_line and "home directory" in log_line:
            user = re.search(r'adduser:.*user (\w+)', log_line)
            if user:
                msg = f"New user created: {user.group(1)}"
                trigger_alert("User Created", "Unknown", msg, "low")
            return

        if "passwd" in log_line and ("password changed" in log_line or "password updated" in log_line):
            user = re.search(r'passwd.*user (\w+)', log_line)
            if user:
                msg = f"Password changed for user {user.group(1)}"
                trigger_alert("Password Changed", "Unknown", msg, "medium")
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
                            if keyword in comm.lower() and pid not in self.reported:
                                trigger_alert("Malicious Process Detected", "Localhost", f"Suspicious process running: {comm} (PID: {pid}, User: {user})", "high")
                                self.reported.add(pid)
            except Exception as e:
                pass
            time.sleep(5)
