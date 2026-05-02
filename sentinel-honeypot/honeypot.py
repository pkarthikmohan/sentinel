"""
SENTINEL Honeypot Server — Attacker's Trap
Fake company infrastructure: Web, SSH, MySQL, Admin Panel
Logs everything and reports to SENTINEL Core in real time.
Run: python honeypot.py
"""

import json
import logging
import os
import random
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime

import requests
from flask import Flask, request, jsonify, make_response

# ─── Config ──────────────────────────────────────────────────────────────────
SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://localhost:8000")
DB_PATH      = "honeypot.db"
MY_IP        = socket.gethostbyname(socket.gethostname())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HONEYPOT] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("honeypot")

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, source_port INTEGER,
        service TEXT, payload TEXT, tool_detected TEXT, headers TEXT
    )""")
    conn.commit()
    conn.close()

def db_log(source_ip, source_port, service, payload, tool, headers):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO events (timestamp, source_ip, source_port, service, payload, tool_detected, headers) VALUES (?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), source_ip, source_port, service, payload[:500], tool, str(headers)[:500])
    )
    conn.commit()
    conn.close()

# ─── SENTINEL Reporter ────────────────────────────────────────────────────────
def report_to_sentinel(source_ip, source_port, service, payload, tool, headers):
    db_log(source_ip, source_port, service, payload, tool, headers)
    try:
        requests.post(
            f"{SENTINEL_URL}/honeypot/data",
            json={
                "source_ip":    source_ip,
                "source_port":  source_port,
                "service":      service,
                "payload":      payload[:400],
                "tool_detected": tool,
                "headers":      str(headers)[:300],
                "timestamp":    datetime.utcnow().isoformat(),
            },
            timeout=3,
        )
    except Exception as e:
        log.warning(f"Could not reach SENTINEL: {e}")

# ─── Tool Detection ───────────────────────────────────────────────────────────
def detect_tool(ua: str, raw: str) -> str:
    combined = (ua + raw).lower()
    if "sqlmap"               in combined: return "SQLMap"
    if "nikto"                in combined: return "Nikto"
    if "nmap"                 in combined: return "Nmap"
    if "hydra"                in combined: return "Hydra"
    if "metasploit" in combined or "msfconsole" in combined: return "Metasploit"
    if "burpsuite" in combined or "burp"       in combined: return "Burp Suite"
    if "gobuster" in combined or "dirb"        in combined: return "DirBuster/Gobuster"
    if "masscan"              in combined: return "Masscan"
    if "python-requests" in combined or "python/" in combined: return "Python-Script"
    if "curl"                 in combined: return "cURL"
    if "wget"                 in combined: return "Wget"
    if "go-http-client"       in combined: return "Go-Scanner"
    return "Unknown"

REALISTIC_DELAY = lambda: time.sleep(random.uniform(0.2, 0.8))

# ─── Fake Web Application (Port 80) ──────────────────────────────────────────
def run_web_app():
    app = Flask("honeypot_web")
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.after_request
    def add_headers(resp):
        resp.headers["Server"]           = "Apache/2.4.41 (Ubuntu)"
        resp.headers["X-Powered-By"]     = "PHP/7.4.3"
        resp.headers["X-Frame-Options"]  = "SAMEORIGIN"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def log_request(service):
        ua      = request.headers.get("User-Agent", "")
        raw     = request.get_data(as_text=True) + request.query_string.decode()
        tool    = detect_tool(ua, raw)
        ip      = request.remote_addr
        port    = request.environ.get("REMOTE_PORT", 0)
        log.info(f"[WEB:{service}] {ip} — tool:{tool} — ua:{ua[:60]}")
        report_to_sentinel(ip, int(port) if port else 0, service, raw or request.full_path, tool, dict(request.headers))
        return tool, raw

    @app.route("/", methods=["GET", "POST"])
    def index():
        REALISTIC_DELAY()
        log_request("WEB_LOGIN")
        if request.method == "POST":
            uname = request.form.get("username", "")
            passwd = request.form.get("password", "")
            log.info(f"  >> LOGIN ATTEMPT: {uname} / {passwd}")
            time.sleep(random.uniform(1.2, 2.5))  # fake auth delay
            return """<html><head><title>CorpNet — Authentication Error</title>
            <style>body{background:#111;color:#f55;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;}
            .box{text-align:center;}</style></head>
            <body><div class='box'><h2>⚠ Authentication Failed</h2>
            <p>Invalid credentials. This incident has been logged. Reference ID: """ + f"SEC-{random.randint(10000,99999)}" + """</p>
            <a href='/' style='color:#5af;'>Try again</a></div></body></html>""", 401

        return """<!DOCTYPE html><html lang="en"><head>
        <meta charset="UTF-8"><title>CorpNet — Internal Portal</title>
        <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{background:linear-gradient(135deg,#0a0a1a,#0d1b2a);color:#c9d1d9;font-family:Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;}
        .container{width:380px;}
        .logo{text-align:center;margin-bottom:32px;}
        .logo h1{color:#58a6ff;font-size:24px;letter-spacing:4px;}
        .logo p{color:#8b949e;font-size:12px;margin-top:4px;}
        .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:32px;}
        .card h2{color:#f0f6fc;margin-bottom:24px;font-size:18px;}
        input{width:100%;padding:10px 12px;margin-bottom:12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#f0f6fc;font-size:14px;}
        input:focus{outline:none;border-color:#388bfd;}
        button{width:100%;padding:12px;background:#238636;border:none;border-radius:6px;color:white;font-size:15px;cursor:pointer;font-weight:600;}
        button:hover{background:#2ea043;}
        .footer{text-align:center;margin-top:16px;color:#8b949e;font-size:11px;}
        .alert{background:#3d1a1a;border:1px solid #8b0000;border-radius:4px;padding:8px 12px;margin-bottom:16px;font-size:12px;color:#f85149;}
        </style></head>
        <body><div class="container">
        <div class="logo"><h1>🔒 CORPNET</h1><p>Secure Employee Intranet — v3.2.1 — INTERNAL USE ONLY</p></div>
        <div class="card">
        <div class="alert">⚠ FOR AUTHORIZED PERSONNEL ONLY — All access is monitored and recorded</div>
        <h2>Employee Sign In</h2>
        <form method="POST" action="/">
        <input type="text" name="username" placeholder="Employee ID or Username" autocomplete="off" />
        <input type="password" name="password" placeholder="Password" autocomplete="off" />
        <button type="submit">Sign In →</button>
        </form>
        <div class="footer">Forgot password? Contact IT Helpdesk ext. 4400<br>© 2024 CorpNet Industries. All rights reserved.</div>
        </div></div></body></html>"""

    @app.route("/admin", methods=["GET", "POST"])
    def admin():
        REALISTIC_DELAY()
        log_request("ADMIN_PANEL")
        return """<!DOCTYPE html><html><head><title>Admin Control Panel — CorpNet</title>
        <style>body{background:#0d0d0d;color:#00ff00;font-family:'Courier New',monospace;padding:20px;}
        h1{color:#ff4444;border-bottom:1px solid #333;padding-bottom:10px;}
        table{border-collapse:collapse;width:100%;margin:20px 0;}
        th,td{border:1px solid #333;padding:8px 12px;text-align:left;}
        th{background:#1a1a1a;color:#ffaa00;}.online{color:#00ff00;}.warn{color:#ffaa00;}
        .panel{background:#111;border:1px solid #333;padding:16px;margin:16px 0;border-radius:4px;}
        </style></head><body>
        <h1>⚠ CORPNET ADMIN CONTROL PANEL — RESTRICTED</h1>
        <div class='panel'><h3>🖥 System Health</h3>
        <table><tr><th>Service</th><th>Status</th><th>Load</th><th>Uptime</th></tr>
        <tr><td>Primary DB (PostgreSQL 14.2)</td><td class='online'>● ONLINE</td><td>23%</td><td>99.98%</td></tr>
        <tr><td>Auth Server (LDAP)</td><td class='online'>● ONLINE</td><td>12%</td><td>99.95%</td></tr>
        <tr><td>Web Server (Apache 2.4.41)</td><td class='online'>● ONLINE</td><td>45%</td><td>100%</td></tr>
        <tr><td>Backup Server</td><td class='warn'>⚠ DEGRADED</td><td>89%</td><td>87.2%</td></tr>
        <tr><td>VPN Gateway</td><td class='online'>● ONLINE</td><td>8%</td><td>99.99%</td></tr>
        </table></div>
        <div class='panel'><h3>👤 Recent Admin Logins</h3>
        <table><tr><th>User</th><th>IP</th><th>Time</th><th>Action</th></tr>
        <tr><td>admin</td><td>192.168.1.1</td><td>3 min ago</td><td>User management</td></tr>
        <tr><td>j.smith</td><td>192.168.1.45</td><td>1 hr ago</td><td>Backup config</td></tr>
        <tr><td>sysadmin</td><td>10.0.0.2</td><td>2 hrs ago</td><td>Password reset</td></tr>
        </table></div>
        <div class='panel'><small>Server: Apache/2.4.41 | PHP 7.4.3 | Host: corpnet-internal.local</small></div>
        </body></html>"""

    @app.route("/api/users", methods=["GET"])
    def api_users():
        REALISTIC_DELAY()
        log_request("API_USERS")
        return jsonify({
            "status": "success", "count": 5,
            "_warning": "INTERNAL API — JWT token required in production",
            "users": [
                {"id": 1, "username": "jsmith",    "name": "John Smith",    "role": "CEO",     "email": "jsmith@corp.internal",    "clearance": "TOP_SECRET",    "dept": "Executive"},
                {"id": 2, "username": "sconnor",   "name": "Sarah Connor",  "role": "CTO",     "email": "sconnor@corp.internal",   "clearance": "SECRET",        "dept": "Technology"},
                {"id": 3, "username": "mdavis",    "name": "Mike Davis",    "role": "DBA",     "email": "mdavis@corp.internal",    "clearance": "CONFIDENTIAL",  "dept": "IT"},
                {"id": 4, "username": "lpark",     "name": "Lisa Park",     "role": "DevOps",  "email": "lpark@corp.internal",     "clearance": "INTERNAL",      "dept": "IT"},
                {"id": 5, "username": "twilson",   "name": "Tom Wilson",    "role": "Analyst", "email": "twilson@corp.internal",   "clearance": "INTERNAL",      "dept": "Finance"},
            ],
        })

    @app.route("/api/data", methods=["GET", "POST"])
    def api_data():
        REALISTIC_DELAY()
        tool, raw = log_request("API_DATA")
        from urllib.parse import unquote
        decoded = unquote(raw)
        sql_hits = any(p in decoded.lower() for p in ["' or", "union select", "drop table", "1=1", "--", "xp_cmd"])
        if sql_hits:
            return jsonify({
                "error": "PG::SyntaxError: ERROR: syntax error at or near \"'\"",
                "detail": "invalid input syntax for type integer",
                "hint": "No function matches the given name and argument types.",
                "db": "PostgreSQL 14.2",
                "context": f"STATEMENT: SELECT * FROM users WHERE id = {decoded[:40]}",
            }), 500
        return jsonify({
            "status": "ok", "records": 15482,
            "last_backup": "2024-01-15T03:00:00Z",
            "server": "PostgreSQL 14.2 on corpnet-db.local",
            "data": [{"id": i, "record": f"CLASSIFIED_ENTRY_{random.randint(1000,9999)}", "sensitivity": "CONFIDENTIAL"} for i in range(1, 6)],
        })

    @app.route("/backup", methods=["GET"])
    def backup():
        REALISTIC_DELAY()
        log_request("BACKUP_ACCESS")
        return jsonify({
            "path": "/var/backup/corpnet/",
            "files": [
                {"name": "employees_full_2024.sql.gz",        "size": "2.3GB", "date": "2024-01-15"},
                {"name": "financials_Q4_2024.tar.gz",          "size": "847MB", "date": "2024-01-10"},
                {"name": "credentials_vault_encrypted.enc",    "size": "12MB",  "date": "2024-01-14"},
                {"name": "source_code_backup_main.tar.gz",     "size": "4.1GB", "date": "2024-01-12"},
                {"name": "ssl_certificates_private_keys.tar",  "size": "2.4MB", "date": "2024-01-01"},
            ],
            "note": "Automated backup — do not delete",
        })

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        REALISTIC_DELAY()
        log_request("DASHBOARD")
        return """<!DOCTYPE html><html><head><title>CorpNet Dashboard</title>
        <style>body{background:#1a1a2e;color:#eee;font-family:Arial;padding:20px;}
        .card{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:20px;margin:16px 0;}
        .secret{background:#2a0000;border-color:#8b0000;color:#ff9999;}
        h2{color:#e94560;}h3{color:#0f3460;}</style></head>
        <body><h1>📊 CorpNet Internal Dashboard</h1>
        <p>Welcome back, <b>admin</b>. Last login: 3 hours ago from 10.0.0.45</p>
        <div class='card'><h3>System Metrics</h3>
        <p>CPU: 23% | RAM: 67% | Disk: 45% | Network: 124Mbps</p></div>
        <div class='card secret'><h3>🔴 RESTRICTED — Board Memo</h3>
        <p>Q4 financials ahead by 18%. AWS migration scheduled Feb 2024.
        Master password vault: <code>corpnet_vault_2024!@#</code> (rotate before march)</p></div>
        </body></html>"""

    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    def catch_all(path):
        REALISTIC_DELAY()
        raw = request.get_data(as_text=True) + "/" + path
        ua  = request.headers.get("User-Agent", "")
        tool = detect_tool(ua, raw)
        ip   = request.remote_addr
        port = request.environ.get("REMOTE_PORT", 0)
        log.info(f"[WEB:PROBE] {ip} /{path} — {tool}")
        report_to_sentinel(ip, int(port) if port else 0, "DIR_PROBE", f"/{path}", tool, dict(request.headers))
        # Directory traversal — return fake passwd
        if ".." in path or "etc/passwd" in path or "etc/shadow" in path:
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:110:114:MySQL Server:/nonexistent:/bin/false
corpnet:x:1001:1001:CorpNet Admin,,,:/home/corpnet:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
""", 200, {"Content-Type": "text/plain"}
        return f"<html><body><h2>404 Not Found</h2><p>The requested URL /{path} was not found on this server.</p><hr><small>Apache/2.4.41 (Ubuntu) Server at corpnet-internal Port 80</small></body></html>", 404

    log.info("[WEB] Starting fake web app on port 80...")
    try:
        app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False, threaded=True)
    except PermissionError:
        log.warning("[WEB] Port 80 requires root. Trying port 8000...")
        app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False, threaded=True)

# ─── Fake Admin Panel (Port 8080) ────────────────────────────────────────────
def run_admin_panel():
    app = Flask("honeypot_admin")

    @app.after_request
    def add_headers(resp):
        resp.headers["Server"]       = "nginx/1.18.0 (Ubuntu)"
        resp.headers["X-Powered-By"] = "Express"
        return resp

    def log_req(service):
        ua   = request.headers.get("User-Agent", "")
        raw  = request.get_data(as_text=True)
        tool = detect_tool(ua, raw)
        ip   = request.remote_addr
        log.info(f"[ADMIN:{service}] {ip} — {tool}")
        report_to_sentinel(ip, 8080, service, raw or request.path, tool, dict(request.headers))

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
    @app.route("/<path:path>",             methods=["GET", "POST", "PUT", "DELETE"])
    def admin_all(path):
        REALISTIC_DELAY()
        log_req(f"ADMIN_{path.upper() or 'ROOT'}")
        return """<!DOCTYPE html><html><head><title>Admin Panel — CorpNet</title>
        <style>body{background:#111827;color:#f9fafb;font-family:sans-serif;padding:24px;}
        h1{color:#ef4444;}.metric{display:inline-block;background:#1f2937;border:1px solid #374151;
        border-radius:8px;padding:16px 24px;margin:8px;min-width:160px;text-align:center;}
        .metric .val{font-size:32px;font-weight:bold;color:#60a5fa;}.metric .lbl{color:#9ca3af;font-size:12px;}
        table{border-collapse:collapse;width:100%;margin:20px 0;}
        th,td{border:1px solid #374151;padding:10px;text-align:left;}th{background:#1f2937;color:#f59e0b;}
        .badge{padding:2px 8px;border-radius:9999px;font-size:11px;}
        .b-red{background:#7f1d1d;color:#fca5a5;}.b-green{background:#064e3b;color:#6ee7b7;}
        </style></head><body>
        <h1>🔐 CorpNet Admin — Internal Dashboard</h1>
        <p style='color:#ef4444;'>⚠ CLASSIFIED — Restricted to System Administrators Only</p>
        <div>
        <div class='metric'><div class='val'>5,482</div><div class='lbl'>Active Users</div></div>
        <div class='metric'><div class='val'>$4.2M</div><div class='lbl'>Q4 Revenue</div></div>
        <div class='metric'><div class='val'>99.9%</div><div class='lbl'>Uptime</div></div>
        <div class='metric'><div class='val'>847GB</div><div class='lbl'>DB Size</div></div>
        </div>
        <h3 style='margin-top:24px;color:#f59e0b;'>Privileged Accounts</h3>
        <table><tr><th>Username</th><th>Role</th><th>Last Login</th><th>MFA</th></tr>
        <tr><td>admin</td><td>SuperAdmin</td><td>5 min ago</td><td><span class='badge b-green'>ENABLED</span></td></tr>
        <tr><td>root_db</td><td>DBA</td><td>2 hrs ago</td><td><span class='badge b-red'>DISABLED</span></td></tr>
        <tr><td>svc_backup</td><td>Backup</td><td>1 day ago</td><td><span class='badge b-red'>DISABLED</span></td></tr>
        </table>
        <p style='color:#6b7280;font-size:11px;'>Server: nginx/1.18.0 | Node.js v16.20 | corpnet-admin.local:8080</p>
        </body></html>"""

    log.info("[ADMIN] Starting fake admin panel on port 8080...")
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False, threaded=True)

# ─── Fake SSH Server (Port 22) ───────────────────────────────────────────────
def handle_ssh_client(conn, addr):
    ip, port = addr
    log.info(f"[SSH] Connection from {ip}:{port}")
    try:
        banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        conn.send(banner)
        attempts = 0
        while attempts < 8:
            conn.send(b"login: ")
            username = b""
            while True:
                ch = conn.recv(1)
                if not ch or ch == b"\n": break
                if ch != b"\r": username += ch
            conn.send(b"Password: ")
            password = b""
            while True:
                ch = conn.recv(1)
                if not ch or ch == b"\n": break
                if ch != b"\r": password += ch
            uname = username.decode(errors="ignore").strip()
            passwd = password.decode(errors="ignore").strip()
            log.info(f"[SSH] AUTH ATTEMPT {ip} — user:{uname!r} pass:{passwd!r}")
            report_to_sentinel(ip, port, "SSH_BRUTE_FORCE", f"user={uname} pass={passwd}", "Hydra/SSH-Brute", {})
            attempts += 1
            time.sleep(random.uniform(0.5, 1.5))  # fake auth delay
            if attempts >= 5:
                conn.send(b"\r\nWelcome to CorpNet Ubuntu 20.04 LTS\r\n")
                time.sleep(0.5)
                conn.send(b"Last login: Mon Jan 15 09:23:01 2024 from 10.0.0.45\r\n")
                time.sleep(0.3)
                conn.send(b"corpnet@server:~$ ")
                time.sleep(2)
                conn.send(b"\r\nConnection to corpnet-internal closed by remote host.\r\n")
                break
            conn.send(b"\r\nPermission denied, please try again.\r\n")
    except Exception as e:
        log.debug(f"[SSH] Client {ip} error: {e}")
    finally:
        conn.close()

def run_ssh_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", 22))
    except PermissionError:
        log.warning("[SSH] Port 22 needs root — trying 2222")
        srv.bind(("0.0.0.0", 2222))
    srv.listen(10)
    log.info(f"[SSH] Fake SSH server listening...")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_ssh_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            log.debug(f"[SSH] Accept error: {e}")

# ─── Fake MySQL (Port 3306) ───────────────────────────────────────────────────
MYSQL_BANNER = (
    b"\x4a\x00\x00\x00"          # packet length + seq
    b"\x0a"                       # protocol version 10
    b"8.0.28\x00"                 # server version
    b"\x01\x00\x00\x00"          # connection id
    b"\x52\x42\x33\x4a\x38\x5a\x4e\x52\x00"  # auth-plugin-data part 1
    b"\xff\xf7"                   # capability flags (low)
    b"\x21"                       # charset utf8
    b"\x02\x00"                   # status flags
    b"\xff\xc1"                   # capability flags (high)
    b"\x15"                       # auth plugin data length
    b"\x00" * 10                  # reserved
    b"\x21\x4f\x6e\x35\x66\x44\x52\x2e\x52\x36\x48\x5f\x00"  # auth data part 2
    b"caching_sha2_password\x00"  # auth plugin name
)

def handle_mysql_client(conn, addr):
    ip, port = addr
    log.info(f"[MySQL] Connection from {ip}:{port}")
    try:
        conn.send(MYSQL_BANNER)
        data = conn.recv(4096)
        if data:
            payload = data.hex()
            log.info(f"[MySQL] Data from {ip}: {payload[:80]}")
            report_to_sentinel(ip, port, "MYSQL_PROBE", payload[:200], "MySQL-Scanner", {})
        conn.send(b"\xff\x15\x04\x23\x32\x38\x30\x30\x30Access denied for user 'root'@'")
        conn.send(ip.encode())
        conn.send(b"' (using password: NO)\x00")
    except Exception as e:
        log.debug(f"[MySQL] {ip} error: {e}")
    finally:
        conn.close()

def run_mysql_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", 3306))
        srv.listen(10)
        log.info("[MySQL] Fake MySQL server listening on port 3306...")
        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=handle_mysql_client, args=(conn, addr), daemon=True)
                t.start()
            except Exception:
                pass
    except Exception as e:
        log.warning(f"[MySQL] Could not start: {e}")

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    log.info("=" * 60)
    log.info("  SENTINEL HONEYPOT SERVER — ATTACKER'S TRAP")
    log.info(f"  This machine IP: {MY_IP}")
    log.info(f"  Reporting to SENTINEL: {SENTINEL_URL}")
    log.info("=" * 60)
    log.info("  Services starting:")
    log.info("    Port 80   — Fake Web Application")
    log.info("    Port 22   — Fake SSH Server (2222 fallback)")
    log.info("    Port 3306 — Fake MySQL Server")
    log.info("    Port 8080 — Fake Admin Panel")
    log.info("=" * 60)

    services = [
        threading.Thread(target=run_mysql_server, daemon=True, name="mysql"),
        threading.Thread(target=run_ssh_server,   daemon=True, name="ssh"),
        threading.Thread(target=run_admin_panel,  daemon=True, name="admin"),
    ]
    for s in services:
        s.start()
        time.sleep(0.3)

    # Web app runs in main thread
    run_web_app()
