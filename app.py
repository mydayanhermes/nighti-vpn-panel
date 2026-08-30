"""
NighTi VPN Panel - Simple VPN Management Panel
Features: User Management, Subscription Links, Config Generation
"""
import os, json, uuid, hashlib, time, sqlite3, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nighti-vpn-panel-secret-2026")
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'

# ============ CONFIG ============
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "nigh1234")
PANEL_NAME = os.environ.get("PANEL_NAME", "NighTi VPN Panel")
DOMAIN = os.environ.get("DOMAIN", "")
SERVER_IP = os.environ.get("SERVER_IP", "")

# ============ DATABASE ============
DB_PATH = os.environ.get("DB_PATH", "vpn_panel.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            uuid TEXT NOT NULL,
            protocol TEXT DEFAULT 'vless',
            traffic_used INTEGER DEFAULT 0,
            traffic_limit INTEGER DEFAULT 0,
            expire_date TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            note TEXT DEFAULT '',
            sub_token TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Insert default settings
    defaults = {
        "server_ip": SERVER_IP,
        "panel_name": PANEL_NAME,
        "vless_path": "/ws",
        "vless_sni": DOMAIN,
        "sub_prefix": "sub",
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()

def get_setting(key):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else ""

def set_setting(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def log_action(action, details=""):
    conn = get_db()
    conn.execute("INSERT INTO logs (action, details) VALUES (?, ?)", (action, details))
    conn.commit()
    conn.close()

# ============ AUTH ============
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["logged_in"] = True
            log_action("login", f"Admin logged in")
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Wrong Credentials!", panel_name=get_setting("panel_name"))
    return render_template("login.html", error=None, panel_name=get_setting("panel_name"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ============ DASHBOARD ============
@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    total = len(users)
    active = sum(1 for u in users if u["enabled"])
    expired = sum(1 for u in users if u["expire_date"] and datetime.strptime(u["expire_date"], "%Y-%m-%d") < datetime.now())
    total_traffic = sum(u["traffic_used"] for u in users)
    conn.close()
    config_to_show = None
    if request.args.get("config_username"):
        config_to_show = {
            "username": request.args.get("config_username"),
            "config": request.args.get("config_config"),
            "sub_token": request.args.get("config_sub_token")
        }
    return render_template("dashboard.html",
        users=users, total=total, active=active, expired=expired,
        total_traffic=total_traffic, panel_name=get_setting("panel_name"),
        now=datetime.now(), config_to_show=config_to_show
    )

# ============ USER MANAGEMENT ============
@app.route("/user/add", methods=["POST"])
@login_required
def add_user():
    username = request.form.get("username", "").strip()
    protocol = request.form.get("protocol", "vless")
    traffic_gb = int(request.form.get("traffic_limit", 50))
    expire_days = int(request.form.get("expire_days", 30))
    
    if not username:
        return redirect(url_for("dashboard"))
    
    user_uuid = os.environ.get("VPN_UUID", "732bd802-cc69-4a9f-a792-4da5b2b7118c")
    sub_token = secrets.token_urlsafe(16)
    expire_date = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d")
    traffic_limit = traffic_gb * 1024 * 1024 * 1024
    
    server_ip = os.environ.get("SERVER_IP") or get_setting("server_ip") or "127.0.0.1"
    sni = os.environ.get("vless_sni") or get_setting("vless_sni") or server_ip
    path = os.environ.get("vless_path") if os.environ.get("vless_path") is not None else get_setting("vless_path") or ""
    
    if protocol == "trojan":
        config = f"trojan://{user_uuid}@{server_ip}:443?security=tls&type=ws&path={path}&host={sni}&sni={sni}#{username}"
    else:
        config = f"vless://{user_uuid}@{server_ip}:443?encryption=none&security=tls&sni={sni}&fp=chrome&type=ws&path={path}&host={sni}#{username}"
    
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, uuid, protocol, traffic_limit, expire_date, note, sub_token) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, user_uuid, protocol, traffic_limit, expire_date, "", sub_token)
        )
        conn.commit()
        conn.close()
        log_action("add_user", f"Added user: {username}")
    except sqlite3.IntegrityError:
        pass
    
    return redirect(url_for("dashboard", config_username=username, config_config=config, config_sub_token=sub_token))

@app.route("/user/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if user:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        log_action("delete_user", f"Deleted user: {user['username']}")
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/user/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET enabled = NOT enabled WHERE id=?", (user_id,))
    conn.commit()
    user = conn.execute("SELECT username, enabled FROM users WHERE id=?", (user_id,)).fetchone()
    log_action("toggle_user", f"{'Enabled' if user['enabled'] else 'Disabled'} user: {user['username']}")
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/user/<int:user_id>/reset", methods=["POST"])
@login_required
def reset_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET traffic_used=0 WHERE id=?", (user_id,))
    conn.commit()
    log_action("reset_user", f"Reset traffic for user ID: {user_id}")
    conn.close()
    return jsonify({"success": True})

# ============ CONFIG GENERATION ============
def gen_vless_config(user_uuid, server_ip, sni, path, name):
    return f"""vless://{user_uuid}@{server_ip}:443?encryption=none&security=tls&sni={sni}&fp=chrome&pbk=&type=ws&path={path}&host={sni}#{name}"""

def gen_trojan_config(user_uuid, server_ip, sni, path, name):
    return f"""trojan://{user_uuid}@{server_ip}:443?security=tls&type=ws&path={path}&host={sni}&sni={sni}#{name}"""

@app.route("/config/<sub_token>")
def user_config(sub_token):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE sub_token=?", (sub_token,)).fetchone()
    if not user or not user["enabled"]:
        return "User not found or disabled", 404
    
    # Check expiry
    if user["expire_date"] and datetime.strptime(user["expire_date"], "%Y-%m-%d") < datetime.now():
        return "Subscription expired", 403
    
    server_ip = get_setting("server_ip")
    sni = get_setting("vless_sni") or server_ip
    path = get_setting("vless_path")
    
    if user["protocol"] == "trojan":
        config = gen_trojan_config(user["uuid"], server_ip, sni, path, user["username"])
    else:
        config = gen_vless_config(user["uuid"], server_ip, sni, path, user["username"])
    
    # Return as subscription
    resp = Response(config, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f"attachment; filename={user['username']}.txt"
    return resp

@app.route("/sub/<sub_token>")
def subscription(sub_token):
    """Subscription endpoint for VPN clients"""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE sub_token=?", (sub_token,)).fetchone()
    if not user or not user["enabled"]:
        return "User not found or disabled", 404
    
    if user["expire_date"] and datetime.strptime(user["expire_date"], "%Y-%m-%d") < datetime.now():
        return "Subscription expired", 403
    
    server_ip = get_setting("server_ip")
    sni = get_setting("vless_sni") or server_ip
    path = get_setting("vless_path")
    
    if user["protocol"] == "trojan":
        config = gen_trojan_config(user["uuid"], server_ip, sni, path, user["username"])
    else:
        config = gen_vless_config(user["uuid"], server_ip, sni, path, user["username"])
    
    resp = Response(config, mimetype="text/plain")
    resp.headers["Subscription-Userinfo"] = f"upload=0; download=0; total={user['traffic_limit']}; expire={int(datetime.strptime(user['expire_date'], '%Y-%m-%d').timestamp())}"
    return resp

# ============ SETTINGS ============
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        for key in ["server_ip", "panel_name", "vless_path", "vless_sni", "sub_prefix"]:
            val = request.form.get(key, "")
            if val:
                set_setting(key, val)
        log_action("settings", "Settings updated")
        return redirect(url_for("settings"))
    
    conn = get_db()
    settings_rows = conn.execute("SELECT * FROM settings").fetchall()
    settings_dict = {s["key"]: s["value"] for s in settings_rows}
    conn.close()
    return render_template("settings.html", settings=settings_dict, panel_name=get_setting("panel_name"))

# ============ LOGS ============
@app.route("/logs")
@login_required
def logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("logs.html", logs=logs, panel_name=get_setting("panel_name"))

# ============ API ============
@app.route("/api/users")
@login_required
def api_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    total = len(users)
    active = sum(1 for u in users if u["enabled"])
    total_traffic = sum(u["traffic_used"] for u in users)
    conn.close()
    return jsonify({"total": total, "active": active, "total_traffic": total_traffic})

# ============ PUBLIC PAGES ============
@app.route("/panel")
def panel_public():
    return render_template("panel_public.html", panel_name=get_setting("panel_name"))

# ============ INIT ============
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)


# Sun Aug 30 12:32:31 UTC 2026
