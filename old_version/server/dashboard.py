from flask import Flask, render_template, request, g, flash, redirect, url_for
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages
DATABASE = "ids.db"  # Ensure this is your database file

def get_db():
    """Connects to the SQLite database."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Enables dictionary-like access
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database if it doesn't exist."""
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            
            # Create logs table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            ''')
            
            # Add some sample data with different timestamps for testing
            current_time = datetime.now()
            sample_data = [
                (1, current_time.strftime('%Y-%m-%d %H:%M:%S'), 'LOGIN', '192.168.1.1', 'Successful login', 'low'),
                (1, (current_time - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'), 'PERMISSION_CHANGE', '192.168.1.1', 'User permissions modified', 'medium'),
                (1, (current_time - timedelta(hours=4)).strftime('%Y-%m-%d %H:%M:%S'), 'FAILED_LOGIN', '10.0.0.5', 'Multiple failed login attempts', 'high'),
                (2, (current_time - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'), 'FILE_ACCESS', '192.168.1.2', 'Accessed sensitive file', 'medium'),
                (1, (current_time - timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S'), 'FILE_MODIFICATION', 'Unknown', 'A new file was created: ./server/ids.db-journal', 'medium'),
                (3, (current_time - timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S'), 'SYSTEM_CHANGE', '10.0.0.10', 'System configuration modified', 'high'),
                (2, (current_time - timedelta(days=1, hours=5)).strftime('%Y-%m-%d %H:%M:%S'), 'ACCOUNT_LOCKOUT', '192.168.1.5', 'Account locked after failed attempts', 'high'),
                (3, (current_time - timedelta(hours=12)).strftime('%Y-%m-%d %H:%M:%S'), 'PASSWORD_CHANGE', '192.168.1.10', 'User changed password', 'low')
            ]
            
            cursor.executemany('INSERT INTO logs (user_id, timestamp, event_type, source_ip, message, severity) VALUES (?, ?, ?, ?, ?, ?)', sample_data)
            db.commit()

def get_event_types():
    """Get all unique event types from the database."""
    db = get_db()
    cursor = db.execute("SELECT DISTINCT event_type FROM logs ORDER BY event_type")
    return [row["event_type"] for row in cursor.fetchall()]

def get_source_ips():
    """Get all unique source IPs from the database."""
    db = get_db()
    cursor = db.execute("SELECT DISTINCT source_ip FROM logs ORDER BY source_ip")
    return [row["source_ip"] for row in cursor.fetchall()]

@app.route("/", methods=["GET", "POST"])
def dashboard():
    logs = {"low": [], "medium": [], "high": []}  # Default empty logs
    user_id = None
    error = None
    
    # Get filter options for dropdowns
    event_types = get_event_types()
    source_ips = get_source_ips()
    
    # Default filter values
    filters = {
        "user_id": "",
        "event_type": "",
        "source_ip": "",
        "severity": "",
        "date_from": "",
        "date_to": ""
    }

    if request.method == "POST":
        # Get filter values from form
        filters["user_id"] = request.form.get("user_id", "")
        filters["event_type"] = request.form.get("event_type", "")
        filters["source_ip"] = request.form.get("source_ip", "")
        filters["severity"] = request.form.get("severity", "")
        filters["date_from"] = request.form.get("date_from", "")
        filters["date_to"] = request.form.get("date_to", "")
        
        # Build query conditions
        query_conditions = []
        query_params = []
        
        if filters["user_id"]:
            query_conditions.append("user_id = ?")
            query_params.append(filters["user_id"])
            user_id = filters["user_id"]  # Set for template display
        
        if filters["event_type"]:
            query_conditions.append("event_type = ?")
            query_params.append(filters["event_type"])
        
        if filters["source_ip"]:
            query_conditions.append("source_ip = ?")
            query_params.append(filters["source_ip"])
        
        if filters["severity"]:
            query_conditions.append("severity = ?")
            query_params.append(filters["severity"].lower())
        
        if filters["date_from"]:
            query_conditions.append("timestamp >= ?")
            query_params.append(filters["date_from"] + " 00:00:00")
        
        if filters["date_to"]:
            query_conditions.append("timestamp <= ?")
            query_params.append(filters["date_to"] + " 23:59:59")
        
        # Only execute query if we have at least one filter condition
        if query_conditions:
            try:
                db = get_db()
                query = "SELECT timestamp, event_type, source_ip, message, severity FROM logs"
                
                if query_conditions:
                    query += " WHERE " + " AND ".join(query_conditions)
                
                query += " ORDER BY timestamp DESC"
                
                cursor = db.execute(query, query_params)
                records = cursor.fetchall()

                if not records:
                    flash(f"No logs found matching your filters", "warning")
                else:
                    flash(f"Found {len(records)} log entries matching your criteria", "success")
                
                for record in records:
                    severity = record["severity"].lower()
                    if severity in logs:
                        logs[severity].append(record)
                    else:
                        # Handle case where severity might not match our categories
                        logs["medium"].append(record)
            except Exception as e:
                error = f"Database error: {str(e)}"
                flash(error, "danger")
        else:
            flash("Please select at least one filter criteria", "info")

    return render_template(
        "dashboard.html", 
        logs=logs, 
        user_id=user_id, 
        error=error, 
        event_types=event_types,
        source_ips=source_ips,
        filters=filters
    )

@app.route("/about")
def about():
    """About page with information about the dashboard."""
    return render_template("about.html")

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500
    
if __name__ == "__main__":
    # Initialize the database
    init_db()
    app.run(debug=True, host="0.0.0.0", port=8080)  # Change port here
