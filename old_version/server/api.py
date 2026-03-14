
from flask import Flask, request, jsonify
import sqlite3
import json

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()

    # Create users table if it doesn't exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL
    )
    """)

    # Create logs table if it doesn't exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        event_type TEXT,
        source_ip TEXT,
        message TEXT,
        severity TEXT CHECK(severity IN ('low', 'medium', 'high')),
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()

# Endpoint to add a user
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    conn = sqlite3.connect('ids.db')
    c = conn.cursor()

    try:
        c.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        return jsonify({"message": "User added successfully", "user_id": user_id}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists"}), 400

# Endpoint to add a log
@app.route('/add_log', methods=['POST'])
def add_log():
    data = request.get_json()
    user_id = data.get('user_id')
    event_type = data.get('event_type')
    source_ip = data.get('source_ip')
    message = data.get('message')
    severity = data.get('severity')

    if not all([user_id, event_type, source_ip, message, severity]):
        return jsonify({"error": "All fields are required"}), 400

    if severity not in ['low', 'medium', 'high']:
        return jsonify({"error": "Invalid severity level"}), 400

    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute("""
    INSERT INTO logs (user_id, event_type, source_ip, message, severity)
    VALUES (?, ?, ?, ?, ?)
    """, (user_id, event_type, source_ip, message, severity))

    conn.commit()
    log_id = c.lastrowid
    conn.close()

    return jsonify({"message": "Log added successfully", "log_id": log_id}), 201

# Function to send user data to the API (from client or script)
if __name__ == "__main__":
    # Initialize the database tables
    init_db()

    # Run the Flask app
    app.run(debug=True, host="0.0.0.0", port=5000)
