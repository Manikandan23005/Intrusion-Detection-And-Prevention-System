import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import threading
import time
import os


recv = ""
with open("config.json","r") as file:
    data = json.load(file)
    recv = data['notification_email']

def send_email(subject, body):
    sender_email = "ids.detection.in007@gmail.com"
    receiver_email = recv
    password = "asvtsrbghsznnbyb"

    message = MIMEMultipart("alternative")
    message["From"] = f"IDS Notification <{sender_email}>"
    message["To"] = receiver_email
    message["Subject"] = subject

    text = f"""\
{subject}

{body}
"""

    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <div style="border: 1px solid #ddd; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto;">
      <h2 style="color: #2e6da4;"> Intrusion Detection Alert</h2>
      <p><strong>Subject:</strong> {subject}</p>
      <p>{body}</p>
      <hr>
      <p style="font-size: 0.9em; color: #888;">This is an automated message from your Intrusion Detection System.</p>
    </div>
  </body>
</html>
"""

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    message.attach(part1)
    message.attach(part2)

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(message)
        server.quit()
        print("Alert sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def add_log(user_id, event_type, source_ip, message, severity):
    api_url = os.getenv("API_URL", "http://127.0.0.1:5000")
    url = f"{api_url}/add_log"
    headers = {"Content-Type": "application/json"}
    payload = {
        "user_id": user_id,
        "event_type": event_type,
        "source_ip": source_ip,
        "message": message,
        "severity": severity
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    if response.status_code == 201:
        print(f"Log added successfully with ID {response.json()['log_id']}")
    else:
        print(f"Failed to add log: {response.json()['error']}")

def block_ip_temporarily(ip_address, duration=10):
    try:
        # Check if sudo is available/needed
        cmd_add = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
            cmd_add.insert(0, "sudo")
        
        subprocess.run(cmd_add, check=True)
        print(f"[INFO] Blocked IP: {ip_address} for {duration} seconds.")
        
        time.sleep(duration)

        cmd_del = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        if subprocess.run(["which", "sudo"], capture_output=True).returncode == 0:
            cmd_del.insert(0, "sudo")

        subprocess.run(cmd_del, check=True)
        print(f"[INFO] Unblocked IP: {ip_address}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {e}")

def block_ip(ip_address, duration=10):
    thread = threading.Thread(target=block_ip_temporarily, args=(ip_address, duration))
    thread.start()
    
