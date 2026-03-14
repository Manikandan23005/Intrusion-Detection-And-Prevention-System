import time
import subprocess
import os
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from alert import send_email, add_log, block_ip
import json
uid=0
ip=''
with open('config.json') as file:
    data = json.load(file)
    uid=(data['user_id'])

class IntrusionHandler(FileSystemEventHandler):
    def __init__(self):
        self.recent_events = {}

    def should_ignore(self, path):
        return any(path.endswith(ext) for ext in ['.swp', '.tmp', '~'])

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
                print(f"[DEBUG] Modified: {event.src_path}")
             #   send_email("Intrusion Detected!", f"A file was modified: {event.src_path}")
                add_log(uid,"File Mofification","Unknown",f"User Modifies a file : {event.src_path}","low")
    def on_created(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            if self.should_alert(event.src_path):
                print(f"[DEBUG] Created: {event.src_path}")
             #  send_email("Intrusion Detected!", f"A new file was created: {event.src_path}")
                add_log(uid,"File Mofification","Unknown",f"A new file was created: {event.src_path}","low")
class IntrusionMonitor:
    def __init__(self, path):
        self.event_handler = IntrusionHandler()
        self.observer = Observer()
        self.path = path

    def run(self):
        print(f"[INFO] Monitoring started on {self.path}")
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
    f_count=0
    def __init__(self):
        self.journalctl = subprocess.Popen(
            ['journalctl', '-f', '-n', '0'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    def start(self):
        print("[INFO] Starting journalctl auth monitor...")
        for line in self.journalctl.stdout:
            self.parse_log(line.strip())

    def parse_log(self, log_line):
        # ✅ SSH login successful (local or remote)
        if "Accepted password for" in log_line:
            match = re.search(r"Accepted password for (\w+) from ([\d\.]+)", log_line)
            ip=""
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
            print(msg)
            send_email("SSH Login Successful", msg)
            add_log(uid,"Login Attempt","Unknown or Local" if ip=="" else ip ,msg,"medium")
            return

        # ❌ SSH login failed (local or remote)
        if "Failed password for" in log_line:
            ip=""
            AuthLogMonitor.f_count+=1 
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
            if AuthLogMonitor.f_count >3 :
                block_ip(ip,10)
            print(msg)
            send_email("SSH Login Failed", msg)
            add_log(uid,"Login Attempt","Unknown or Local" if ip=="" else ip ,msg,"high")
            return

        # ⚙️ Root shell accessed via sudo -i
        if "sudo" in log_line and "COMMAND=/usr/bin/zsh" in log_line:
            user = re.search(r'^.*sudo\[\d+\]: (\w+)', log_line)
            if user:
                msg = f"Root shell accessed by user {user.group(1)}"
                print(msg)
                send_email("Root Shell Access", msg)
                add_log(uid,"Root Shell Access","Unknown" ,msg,"high")
            return
        

        # 👤 New user added
        if "adduser" in log_line and "home directory" in log_line:
            user = re.search(r'adduser:.*user (\w+)', log_line)
            if user:
                msg = f"New user created: {user.group(1)}"
                print(msg)
                send_email("User Created", msg)
                add_log(uid,"User Created","Unknown",msg,"low")
            return

        # ❌ User deleted
        if "deluser" in log_line and "remove user" in log_line:
            user = re.search(r"remove user '(\w+)'", log_line)
            if user:
                msg = f"User deleted: {user.group(1)}"
                print(msg)
                send_email("User Deleted", msg)
                add_log(uid,"User Deleted","Unknown",msg,"medium")
            return

        # 🔑 Password changed
        if "passwd" in log_line and ("password changed" in log_line or "password updated" in log_line):
            user = re.search(r'passwd.*user (\w+)', log_line)
            if user:
                msg = f"Password changed for user {user.group(1)}"
                print(msg)
                send_email("Password Changed", msg)
                add_log(uid,"Password Changed","Unknown",msg,"medium")
            return

        # 🔄 User modified
        if "usermod" in log_line:
            user = re.search(r'usermod.*user (\w+)', log_line)
            if user:
                msg = f"User modified: {user.group(1)}"
                print(msg)
                send_email("User Modified", msg)
                add_log(uid,"User Modified","Unknown" ,msg,"low")
            return

        # 👥 Group change
        if "add '" in log_line and "to group" in log_line:
            user = re.search(r"add '(\w+)' to group '(\w+)'", log_line)
            if user:
                msg = f"User '{user.group(1)}' added to group '{user.group(2)}'"
                print(msg)
                send_email("User Group Change", msg)
                add_log(uid,"User Group Changed","Unknown" ,msg,"low")
            return

        # 🚫 Ignore unrelated logs
        return
