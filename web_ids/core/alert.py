import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import threading
import time
import os
from core.db import get_setting, add_log

def send_email(subject, body):
    receiver_email = get_setting("notification_email")
    sender_email = get_setting("smtp_email", "ids.detection.in007@gmail.com")
    password = get_setting("smtp_password", "asvtsrbghsznnbyb").replace(" ", "")
    
    if not receiver_email:
        print("[WARN] No notification email set. Skipping alert.")
        return

    message = MIMEMultipart("alternative")
    message["From"] = f"IDS Notification <{sender_email}>"
    message["To"] = receiver_email
    message["Subject"] = subject

    html = f"""\
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <div style="border: 1px solid #ddd; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto;">
          <h2 style="color: #e53e3e;"> Intrusion Detection Alert</h2>
          <p><strong>Subject:</strong> {subject}</p>
          <p>{body}</p>
          <hr>
          <p style="font-size: 0.9em; color: #888;">Automated message from your Local IDS Dashboard.</p>
        </div>
      </body>
    </html>
    """

    part = MIMEText(html, "html", "utf-8")
    message.attach(part)

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(message)
        server.quit()
        print("[INFO] Alert email sent successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def block_ip_temporarily(ip_address, duration=10):
    try:
        if not ip_address or ip_address == "Unknown":
            return

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
        print(f"[ERROR] iptables command failed: {e}")

def block_ip(ip_address, duration=60):
    thread = threading.Thread(target=block_ip_temporarily, args=(ip_address, duration), daemon=True)
    thread.start()

def trigger_alert(event_type, source_ip, message, severity):
    if get_setting("monitoring_active", "true") == "false":
        return

    # Log directly to local SQLite DB
    add_log(event_type, source_ip, message, severity)

    # In a real environment, send email for medium/high severity
    if severity in ['medium', 'high']:
        send_email(f"IDS Alert: {event_type}", f"High urgency event detected. IP: {source_ip} \\n Details: {message}")
