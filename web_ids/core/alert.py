import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.db import get_setting

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

