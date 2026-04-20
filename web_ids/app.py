from flask import Flask, render_template, request, redirect, flash
import threading
import os
import sys

from werkzeug.security import generate_password_hash, check_password_hash
from flask import url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from core.db import init_db, get_logs, set_setting, get_setting, create_user, get_user_by_username, delete_log, get_log_stats, get_user_by_id
from core.alert import send_email

app = Flask(__name__)
app.secret_key = "super_secret_ids_key"
app.config['TEMPLATES_AUTO_RELOAD'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['id'])
        self.username = user_data['username']
        self.api_key = user_data.get('api_key')

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(int(user_id))
    if user_data:
        return User(user_data)
    return None

@app.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if create_user(username, generate_password_hash(password)):
            flash("Account created! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already exists.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_user_by_username(request.form.get("username"))
        if user and check_password_hash(user['password_hash'], request.form.get("password")):
            login_user(User(user))
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    limit = 10
    offset = (page - 1) * limit
    
    user_id = current_user.id
    
    logs, total_logs = get_logs(user_id=user_id, limit=limit, offset=offset, severity=severity if severity else None)
    total_pages = (total_logs + limit - 1) // limit
    if total_pages == 0:
        total_pages = 1
        
    stats = get_log_stats(user_id=user_id)
    monitoring_active = get_setting("monitoring_active", "true") == "true"
        
    return render_template("dashboard.html", logs=logs, page=page, total_pages=total_pages, severity=severity, total_logs=total_logs, stats=stats, monitoring_active=monitoring_active)

@app.route("/toggle_monitoring", methods=["POST"])
@login_required
def toggle_monitoring():
    current_state = get_setting("monitoring_active", "true")
    new_state = "false" if current_state == "true" else "true"
    set_setting("monitoring_active", new_state)
    status_str = "started" if new_state == "true" else "stopped"
    flash(f"IDS Monitoring has been {status_str}.", "info")
    return redirect(url_for("dashboard"))

@app.route("/delete_log/<int:log_id>", methods=["POST"])
@login_required
def delete_log_route(log_id):
    delete_log(log_id)
    flash(f"Log #{log_id} deleted successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        email = request.form.get("notification_email")
        smtp_email = request.form.get("smtp_email")
        smtp_password = request.form.get("smtp_password")
        
        if email:
            set_setting("notification_email", email.strip())
            if smtp_email:
                set_setting("smtp_email", smtp_email.strip())
            if smtp_password:

                cleaned_password = smtp_password.replace(" ", "")
                set_setting("smtp_password", cleaned_password)
                
            flash("Settings updated successfully!", "success")
        else:
            flash("Notification email cannot be empty.", "warning")
        return redirect("/settings")

    current_email = get_setting("notification_email", "")
    current_smtp_email = get_setting("smtp_email", "ids.detection.in007@gmail.com")
    current_smtp_password = get_setting("smtp_password", "")
    
    from core.db import get_db
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT api_key FROM users WHERE id = ?", (current_user.id,))
    row = c.fetchone()
    conn.close()
    api_key = row['api_key'] if row else None

    return render_template("settings.html", current_email=current_email, current_smtp_email=current_smtp_email, current_smtp_password=current_smtp_password, api_key=api_key)

@app.route("/test_email", methods=["POST"])
@login_required
def test_email():
    try:
        from core.alert import send_email
        send_email("IDS Setup Verification", "🎉 Success! Your email is perfectly configured and the IDS can now communicate with you.")
        flash("System has dispatched a test email. Please check your inbox!", "success")
    except Exception as e:
        flash(f"Test email failed: {str(e)}", "danger")
    return redirect(url_for("settings"))

import subprocess
from flask import send_file, jsonify
from core.db import get_user_by_api_key

@app.route('/download_agent')
@login_required
def download_agent():

    path_to_agent = os.path.join(os.path.dirname(__file__), 'downloads', 'ids_agent.py')
    if os.path.exists(path_to_agent):
        return send_file(path_to_agent, as_attachment=True)
    return "Agent file not found.", 404

@app.route('/api/v1/alerts', methods=['POST'])
def receive_alert():
    data = request.json
    api_key = data.get('api_key')
    
    if not api_key:
        return jsonify({"status": "error", "message": "Missing API key"}), 400
        
    user = get_user_by_api_key(api_key)
    if not user:
        return jsonify({"status": "error", "message": "Invalid API key"}), 401
    
    event_type = data.get('alert_type', 'Unknown Event')
    message = data.get('message', '')
    severity = data.get('severity', 'low')
    source_ip = data.get('ip_address', 'Unknown')
    
    if get_setting("monitoring_active", "true") == "true":
        from core.db import add_log
        add_log(event_type, source_ip, message, severity, user['id'])

        if severity in ['medium', 'high']:
            send_email(f"IDS Alert: {event_type}", f"Remote alert detected. IP: {source_ip} \\n Details: {message}")

    return jsonify({"status": "Alert Received"}), 201

@app.route("/processes")
@login_required
def processes():
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('filter', '')
    limit = 10

    user_id = current_user.id
    from core.db import get_logs
    logs, total_logs = get_logs(user_id=user_id, limit=1, offset=0)
    agent_setup = total_logs > 0

    import subprocess
    import re
    malicious_keywords = ['nmap', 'nc', 'netcat', 'hydra', 'sqlmap', 'john', 'metasploit', 'xmrig', 'cgminer']
    
    try:
        result = subprocess.run(["ps", "-eo", "user,pid,pcpu,pmem,comm", "--sort=-pcpu"], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:] 
        
        all_processes = []
        for line in lines:
            parts = line.split(None, 4)
            if len(parts) == 5:
                user, pid, pcpu, pmem, comm = parts
                
                is_malicious = False
                for keyword in malicious_keywords:
                    if re.search(rf'\b{keyword}\b', comm.lower()):
                        is_malicious = True
                        break
                        
                category = "Malicious" if is_malicious else "System"
                
                all_processes.append({
                    'user': user,
                    'category': category,
                    'pid': pid,
                    'pcpu': float(pcpu),
                    'pmem': float(pmem),
                    'comm': comm
                })
    except Exception as e:
        all_processes = []

    filtered_processes = []
    for p in all_processes:
        if filter_type == 'high_cpu' and p['pcpu'] < 5.0:
            continue
        if filter_type == 'malicious' and p['category'] != 'Malicious':
            continue
        filtered_processes.append(p)

    total_logs_processes = len(filtered_processes)
    total_pages = (total_logs_processes + limit - 1) // limit
    if total_pages == 0:
        total_pages = 1

    offset = (page - 1) * limit
    paginated_processes = filtered_processes[offset:offset + limit]

    return render_template("processes.html", processes=paginated_processes, page=page, total_pages=total_pages, filter_type=filter_type, agent_setup=agent_setup)

@app.route('/api/v1/ips_events', methods=['POST'])
def receive_ips_event():
    data = request.json
    api_key = data.get('api_key')
    user = get_user_by_api_key(api_key)
    if not user: return jsonify({"status": "error"}), 401
    if get_setting("monitoring_active", "true") == "true":
        from core.db import add_ips_event
        add_ips_event(data.get('action'), data.get('target'), data.get('details'), user['id'])
    return jsonify({"status": "Success"}), 201

@app.route('/api/v1/commands', methods=['GET'])
def get_commands():
    api_key = request.args.get('api_key')
    if not api_key: return jsonify({"status": "error"}), 400
    user = get_user_by_api_key(api_key)
    if not user: return jsonify({"status": "error"}), 401
    from core.db import get_pending_commands
    cmds = get_pending_commands(user['id'])
    return jsonify({"commands": cmds}), 200

@app.route('/api/v1/commands/<int:cmd_id>/complete', methods=['POST'])
def complete_command(cmd_id):
    data = request.json
    api_key = data.get('api_key')
    user = get_user_by_api_key(api_key)
    if not user: return jsonify({"status": "error"}), 401
    from core.db import complete_agent_command
    complete_agent_command(cmd_id, user['id'])
    return jsonify({"status": "Success"}), 200

@app.route("/ips")
@login_required
def ips():
    page = request.args.get('page', 1, type=int)
    from core.db import get_ips_events, get_logs
    logs, total_logs = get_logs(user_id=current_user.id, limit=1, offset=0)
    agent_setup = total_logs > 0
    limit = 20
    offset = (page - 1) * limit
    events = get_ips_events(current_user.id, limit=limit, offset=offset)
    total_pages = 1
    return render_template("ips.html", events=events, page=page, total_pages=total_pages, agent_setup=agent_setup)

@app.route("/block_ip", methods=["POST"])
@login_required
def block_ip():
    ip = request.form.get('ip')
    if ip:
        from core.db import add_agent_command
        add_agent_command('block_ip', ip, current_user.id)
        flash(f"Block command sent for {ip}. It will be executed shortly by the agent.", "success")
    return redirect(request.referrer or url_for('ips'))

@app.route("/unblock_ip", methods=["POST"])
@login_required
def unblock_ip():
    ip = request.form.get('ip')
    if ip:
        from core.db import add_agent_command
        add_agent_command('unblock_ip', ip, current_user.id)
        flash(f"Unblock command sent for {ip}. It will be executed shortly by the agent.", "success")
    return redirect(request.referrer or url_for('ips'))

@app.route("/kill_process", methods=["POST"])
@login_required
def kill_process():
    pid = request.form.get('pid')
    if pid:
        from core.db import add_agent_command
        add_agent_command('kill_process', pid, current_user.id)
        flash(f"Kill command sent for process {pid}.", "success")
    return redirect(request.referrer or url_for('ips'))

if __name__ == "__main__":

    init_db()


    os.makedirs(os.path.join(os.path.dirname(__file__), 'downloads'), exist_ok=True)

    app.run(debug=True, host="0.0.0.0", port=9090)
