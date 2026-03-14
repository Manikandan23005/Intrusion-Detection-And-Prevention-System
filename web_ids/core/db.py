import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'ids.db')

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        api_key TEXT UNIQUE
    )
    """)
    
    # Logs table
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT,
        source_ip TEXT,
        message TEXT,
        severity TEXT CHECK(severity IN ('low', 'medium', 'high')),
        user_id INTEGER NULL
    )
    """)
    
    # Settings table
    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    
    # IPS Events table
    c.execute("""
    CREATE TABLE IF NOT EXISTS ips_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action TEXT,
        target TEXT,
        details TEXT,
        user_id INTEGER
    )
    """)
    
    # Agent Commands table (for unblocking IPs etc)
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command TEXT,
        target TEXT,
        status TEXT DEFAULT 'pending',
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Migrate existing logs table to add user_id column if it doesn't exist
    try:
        c.execute("ALTER TABLE logs ADD COLUMN user_id INTEGER NULL")
    except sqlite3.OperationalError:
        pass  # Column already exists
        
    # Migrate existing users table to add api_key column if it doesn't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
        
    conn.commit()
    conn.close()

def create_user(username, password_hash):
    import uuid
    api_key = str(uuid.uuid4())
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)", (username, password_hash, api_key))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_api_key(api_key):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def add_log(event_type, source_ip, message, severity, user_id=None):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO logs (event_type, source_ip, message, severity, user_id)
    VALUES (?, ?, ?, ?, ?)
    """, (event_type, source_ip, message, severity, user_id))
    conn.commit()
    conn.close()

def get_logs(user_id, limit=10, offset=0, severity=None):
    conn = get_db()
    c = conn.cursor()
    
    query = "SELECT logs.id, DATETIME(logs.timestamp, 'localtime') as timestamp, logs.event_type, logs.source_ip, logs.message, logs.severity, logs.user_id, users.username FROM logs LEFT JOIN users ON logs.user_id = users.id WHERE logs.user_id = ?"
    params = [user_id]
    
    if severity:
        query += " AND logs.severity = ?"
        params.append(severity)
        
    query += " ORDER BY logs.timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    c.execute(query, tuple(params))
    rows = [dict(row) for row in c.fetchall()]
    
    count_query = "SELECT COUNT(*) as total FROM logs WHERE user_id = ?"
    count_params = [user_id]
    if severity:
        count_query += " AND logs.severity = ?"
        count_params.append(severity)
        
    c.execute(count_query, tuple(count_params))
    total = c.fetchone()['total']
    conn.close()
    return rows, total

def delete_log(log_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()

def get_log_stats(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) as count FROM logs WHERE user_id = ? GROUP BY severity", (user_id,))
    rows = c.fetchall()
    
    stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
    for row in rows:
        stats[row['severity']] = row['count']
        stats['total'] += row['count']
        
    conn.close()
    return stats

def get_setting(key, default=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row['value'] if row else default

def set_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, value))
    conn.commit()
    conn.close()

def add_ips_event(action, target, details, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO ips_events (action, target, details, user_id)
    VALUES (?, ?, ?, ?)
    """, (action, target, details, user_id))
    conn.commit()
    conn.close()

def get_ips_events(user_id, limit=20, offset=0):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    SELECT id, DATETIME(timestamp, 'localtime') as timestamp, action, target, details
    FROM ips_events
    WHERE user_id = ?
    ORDER BY timestamp DESC LIMIT ? OFFSET ?
    """, (user_id, limit, offset))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def add_agent_command(command, target, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO agent_commands (command, target, user_id)
    VALUES (?, ?, ?)
    """, (command, target, user_id))
    conn.commit()
    conn.close()

def get_pending_commands(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    SELECT id, command, target FROM agent_commands
    WHERE user_id = ? AND status = 'pending'
    """, (user_id,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def complete_agent_command(cmd_id, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    UPDATE agent_commands SET status = 'completed'
    WHERE id = ? AND user_id = ?
    """, (cmd_id, user_id))
    conn.commit()
    conn.close()
