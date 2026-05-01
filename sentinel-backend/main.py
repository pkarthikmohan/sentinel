"""
SENTINEL Core — Cybersecurity Demonstration Backend
FastAPI + WebSocket + Scapy + SQLite + Ollama (Mistral)
"""

import asyncio
import json
import logging
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("sentinel")

# ─── SQLite Setup ────────────────────────────────────────────────────────────
DB_PATH = "sentinel.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            source_ip TEXT,
            target_service TEXT,
            severity TEXT,
            payload TEXT,
            blocked INTEGER DEFAULT 0,
            ai_analysis TEXT
        )
    """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            service TEXT,
            payload TEXT,
            tool_detected TEXT,
            headers TEXT
        )
    """
    )
    conn.commit()
    conn.close()
    log.info("Database initialized.")


def db_log_attack(
    attack_type,
    source_ip,
    target_service,
    severity,
    payload="",
    blocked=False,
    ai_analysis="",
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO attack_logs
           (timestamp, attack_type, source_ip, target_service, severity, payload, blocked, ai_analysis)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            attack_type,
            source_ip,
            target_service,
            severity,
            payload,
            1 if blocked else 0,
            ai_analysis,
        ),
    )
    conn.commit()
    conn.close()


def db_log_honeypot(source_ip, service, payload, tool_detected="", headers=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO honeypot_logs
           (timestamp, source_ip, service, payload, tool_detected, headers)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            source_ip,
            service,
            payload,
            tool_detected,
            headers,
        ),
    )
    conn.commit()
    conn.close()


# ─── State ───────────────────────────────────────────────────────────────────
class SentinelState:
    def __init__(self):
        self.active_threats: int = 0
        self.attacks_detected: int = 0
        self.attacks_blocked: int = 0
        self.blocked_ips: set = set()
        self.attack_detected: bool = False
        self.honeypot_active: bool = False
        self.honeypot_port: int = 8080
        self.attacker_profile: dict = {}
        # Traffic tracking for real Scapy detection
        self.port_scan_tracker: dict = {}   # ip -> {ports: set, first_seen: time}
        self.brute_force_tracker: dict = {}  # ip:port -> {count, first_seen}
        self.syn_flood_tracker: dict = {}    # ip -> {count, first_seen}


state = SentinelState()

# ─── WebSocket Manager ───────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)
        log.info(f"Dashboard connected. Total: {len(self.active_connections)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active_connections:
            self.active_connections.remove(ws)
        log.info(f"Dashboard disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# Global asyncio event loop reference for thread-safe broadcasting
_loop: Optional[asyncio.AbstractEventLoop] = None


def broadcast_from_thread(message: dict):
    """Thread-safe broadcast from Scapy/honeypot threads."""
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), _loop)


# ─── Ollama AI Analysis ──────────────────────────────────────────────────────
async def ollama_analyze(prompt: str, fallback: str = "") -> str:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "http://localhost:11434/api/generate",
                json={"model": "mistral", "prompt": prompt, "stream": False},
            )
            if resp.status_code == 200:
                return resp.json().get("response", fallback).strip()
    except Exception as e:
        log.warning(f"Ollama unavailable: {e}")
    return fallback


def ollama_analyze_sync(prompt: str, fallback: str = "") -> str:
    """Synchronous Ollama call for use in threads."""
    try:
        import requests as req
        resp = req.post(
            "http://localhost:11434/api/generate",
            json={"model": "mistral", "prompt": prompt, "stream": False},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("response", fallback).strip()
    except Exception as e:
        log.warning(f"Ollama unavailable (sync): {e}")
    return fallback


# ─── Defense Engine ──────────────────────────────────────────────────────────
def block_ip_iptables(ip: str):
    """Block an IP using iptables (Linux only)."""
    if ip in state.blocked_ips:
        return
    state.blocked_ips.add(ip)
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=5,
        )
        log.info(f"[BLOCKED] {ip} via iptables")
    except Exception as e:
        log.warning(f"iptables not available (non-Linux or no root): {e}")


async def fire_defense_event(ip: str, attack_type: str, service: str, ai_text: str):
    state.attacks_blocked += 1
    state.active_threats = max(0, state.active_threats - 1)
    await manager.broadcast(
        {
            "type": "defense",
            "data": {
                "timestamp": datetime.utcnow().isoformat(),
                "blocked_ip": ip,
                "attack_type": attack_type,
                "service_protected": service,
                "action": f"IP {ip} blocked at firewall level",
                "ai_analysis": ai_text,
                "stats": {
                    "attacks_detected": state.attacks_detected,
                    "attacks_blocked": state.attacks_blocked,
                    "active_threats": state.active_threats,
                },
            },
        }
    )


async def handle_attack(
    source_ip: str,
    attack_type: str,
    target_service: str,
    severity: str,
    payload: str = "",
):
    state.attacks_detected += 1
    state.active_threats += 1
    state.attack_detected = True

    # AI analysis
    prompt = (
        f"In one sentence, explain this cybersecurity attack and the immediate defense action taken. "
        f"Attack: {attack_type} from IP {source_ip} targeting {target_service}. "
        f"Payload snippet: {payload[:100] if payload else 'N/A'}. Be concise and technical."
    )
    fallback_texts = {
        "PORT_SCAN": f"Port scan detected from {source_ip} — scanning for open services on {target_service}.",
        "BRUTE_FORCE": f"Brute force attack from {source_ip} hammering {target_service} with credential stuffing.",
        "SYN_FLOOD": f"SYN flood from {source_ip} attempting to exhaust {target_service} connection table.",
        "SQL_INJECTION": f"SQL injection probe from {source_ip} attempting database extraction via {target_service}.",
        "DIR_TRAVERSAL": f"Directory traversal from {source_ip} attempting file system access on {target_service}.",
        "NMAP_SCAN": f"Nmap fingerprinting detected from {source_ip} enumerating {target_service}.",
    }
    ai_text = await ollama_analyze(prompt, fallback_texts.get(attack_type, f"Attack {attack_type} from {source_ip}."))

    # Broadcast attack event
    await manager.broadcast(
        {
            "type": "attack",
            "data": {
                "timestamp": datetime.utcnow().isoformat(),
                "attack_type": attack_type,
                "source_ip": source_ip,
                "target_service": target_service,
                "severity": severity,
                "payload": payload[:200] if payload else "",
                "ai_analysis": ai_text,
                "stats": {
                    "attacks_detected": state.attacks_detected,
                    "attacks_blocked": state.attacks_blocked,
                    "active_threats": state.active_threats,
                },
            },
        }
    )

    # Log to DB
    db_log_attack(attack_type, source_ip, target_service, severity, payload, False, ai_text)

    # Auto-defense after short delay
    await asyncio.sleep(1.5)
    block_ip_iptables(source_ip)
    defense_ai = await ollama_analyze(
        f"In one sentence, describe the firewall defense action taken against {attack_type} from {source_ip}.",
        f"Firewall rule deployed — {source_ip} blocked, all packets from this host dropped at kernel level.",
    )
    await fire_defense_event(source_ip, attack_type, target_service, defense_ai)
    db_log_attack(attack_type, source_ip, target_service, severity, payload, True, defense_ai)


# ─── Scapy Packet Sniffer ────────────────────────────────────────────────────
def get_local_ip():
    """Get this machine's primary local IP."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()
SQL_PATTERNS = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|select\s+\*|or\s+1=1|'--|\bexec\b|\bxp_cmdshell\b)",
    re.IGNORECASE,
)
TRAVERSAL_PATTERNS = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)", re.IGNORECASE)
NMAP_PATTERNS = re.compile(r"(nmap|masscan|zmap)", re.IGNORECASE)


def analyze_packet(pkt):
    """Scapy packet callback — detect attacks."""
    try:
        _analyze_packet_inner(pkt)
    except Exception:
        pass


def _analyze_packet_inner(pkt):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.http import HTTP, HTTPRequest

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Ignore our own traffic and loopback
    if src_ip == LOCAL_IP or src_ip.startswith("127.") or src_ip == "localhost":
        return

    now = time.time()

    # ── SYN Flood Detection ──────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = tcp.flags

        if flags == 0x02:  # SYN only
            tracker = state.syn_flood_tracker.setdefault(src_ip, {"count": 0, "first_seen": now})
            tracker["count"] += 1
            # Reset window every 5 seconds
            if now - tracker["first_seen"] > 5:
                tracker["count"] = 1
                tracker["first_seen"] = now
            elif tracker["count"] == 50:  # threshold
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "SYN_FLOOD", "NETWORK LAYER", "CRITICAL"),
                    _loop,
                )

        # ── Port Scan Detection ──────────────────────────────────────────────
        dst_port = tcp.dport
        tracker = state.port_scan_tracker.setdefault(src_ip, {"ports": set(), "first_seen": now, "fired": False})
        if now - tracker["first_seen"] > 10:
            tracker["ports"] = set()
            tracker["first_seen"] = now
            tracker["fired"] = False
        tracker["ports"].add(dst_port)
        if len(tracker["ports"]) > 15 and not tracker["fired"]:
            tracker["fired"] = True
            asyncio.run_coroutine_threadsafe(
                handle_attack(src_ip, "PORT_SCAN", "ALL SERVICES", "HIGH",
                              f"Scanned ports: {list(tracker['ports'])[:10]}"),
                _loop,
            )

        # ── Brute Force Detection ────────────────────────────────────────────
        if flags & 0x02:  # SYN to single port
            key = f"{src_ip}:{dst_port}"
            bt = state.brute_force_tracker.setdefault(key, {"count": 0, "first_seen": now, "fired": False})
            if now - bt["first_seen"] > 10:
                bt["count"] = 0
                bt["first_seen"] = now
                bt["fired"] = False
            bt["count"] += 1
            if bt["count"] > 20 and not bt["fired"]:
                bt["fired"] = True
                svc = {22: "SSH (AUTH SERVER)", 80: "HTTP (API SERVER)", 3306: "MySQL (DATABASE)"}.get(
                    dst_port, f"PORT {dst_port}"
                )
                severity = "CRITICAL" if dst_port == 22 else "HIGH"
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "BRUTE_FORCE", svc, severity, f"Target port: {dst_port}"),
                    _loop,
                )

    # ── HTTP Analysis ────────────────────────────────────────────────────────
    if pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        try:
            path = req.Path.decode(errors="ignore") if req.Path else ""
            host = req.Host.decode(errors="ignore") if req.Host else ""
            ua = req.User_Agent.decode(errors="ignore") if hasattr(req, "User_Agent") and req.User_Agent else ""
            raw = path + host + ua

            # Nmap detection
            if NMAP_PATTERNS.search(ua) or NMAP_PATTERNS.search(raw):
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "NMAP_SCAN", "API SERVER", "HIGH", ua[:100]),
                    _loop,
                )

            # SQL Injection
            if SQL_PATTERNS.search(path) or SQL_PATTERNS.search(raw):
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "SQL_INJECTION", "DATABASE", "CRITICAL", path[:200]),
                    _loop,
                )

            # Directory Traversal
            if TRAVERSAL_PATTERNS.search(path):
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "DIR_TRAVERSAL", "API SERVER", "HIGH", path[:200]),
                    _loop,
                )
        except Exception:
            pass


def start_scapy_sniffer():
    """Start real packet sniffing in a background thread."""
    try:
        from scapy.all import sniff, conf
        log.info(f"[SCAPY] Starting packet sniffer on interface: {conf.iface}")
        log.info(f"[SCAPY] Monitoring from local IP: {LOCAL_IP}")
        sniff(
            prn=analyze_packet,
            store=False,
            filter="tcp or udp",
            stop_filter=lambda _: False,
        )
    except ImportError:
        log.warning("Scapy not installed — packet sniffing disabled.")
    except PermissionError:
        log.warning("No root/admin privileges — packet sniffing disabled. Run as root/admin for real monitoring.")
    except Exception as e:
        log.warning(f"Scapy sniffer error: {e}")


# ─── Honeypot System (mini Flask on separate thread) ────────────────────────
honeypot_thread: Optional[threading.Thread] = None


def start_honeypot_server(port: int = 8080):
    """Launch a fake vulnerable service honeypot."""
    from flask import Flask, request, jsonify
    import time as t

    hp = Flask("honeypot")
    log.info(f"[HONEYPOT] Starting fake service on port {port}")

    def _log_and_report(source_ip, service, payload, headers):
        ua = str(headers.get("User-Agent", ""))
        tool = detect_tool(ua, payload)
        db_log_honeypot(source_ip, service, payload[:500], tool, str(dict(headers))[:500])
        broadcast_from_thread(
            {
                "type": "honeypot",
                "data": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": source_ip,
                    "service": service,
                    "payload": payload[:300],
                    "tool_detected": tool,
                    "user_agent": ua,
                    "intel_update": build_profile_update(source_ip, tool, payload, service),
                },
            }
        )

    def detect_tool(ua: str, payload: str) -> str:
        combined = (ua + payload).lower()
        if "sqlmap" in combined:
            return "SQLMap"
        if "nikto" in combined:
            return "Nikto"
        if "nmap" in combined:
            return "Nmap"
        if "hydra" in combined:
            return "Hydra"
        if "metasploit" in combined or "msfconsole" in combined:
            return "Metasploit"
        if "burp" in combined:
            return "Burp Suite"
        if "gobuster" in combined or "dirb" in combined:
            return "DirBuster/Gobuster"
        if "python-requests" in combined or "python/" in combined:
            return "Python Script"
        if "curl" in combined:
            return "cURL"
        if "wget" in combined:
            return "Wget"
        return "Unknown Tool"

    def build_profile_update(source_ip, tool, payload, service):
        score = min(100, state.attacker_profile.get("threat_score", 0) + random.randint(5, 15))
        state.attacker_profile["threat_score"] = score
        state.attacker_profile.setdefault("ip", source_ip)
        state.attacker_profile.setdefault("tools", set()).add(tool)
        state.attacker_profile.setdefault("services_hit", [])
        if service not in state.attacker_profile["services_hit"]:
            state.attacker_profile["services_hit"].append(service)
        state.attacker_profile.setdefault("commands", [])
        if payload:
            state.attacker_profile["commands"].append(payload[:100])

        return {
            "ip": source_ip,
            "tools": list(state.attacker_profile.get("tools", set())),
            "services_hit": state.attacker_profile.get("services_hit", []),
            "threat_score": score,
            "command": payload[:100] if payload else None,
        }

    t.sleep(0.5)  # brief delay before binding

    # ── Login Page ──────────────────────────────────────────────────────────
    @hp.route("/", methods=["GET", "POST"])
    def index():
        t.sleep(random.uniform(0.3, 0.9))
        if request.method == "POST":
            data = request.get_data(as_text=True)
            _log_and_report(request.remote_addr, "WEB_LOGIN", data, request.headers)
            return """<html><body style='background:#1a1a1a;color:#ff4444;font-family:monospace;'>
            <h2>Authentication Failed</h2><p>Invalid credentials. This incident has been reported.</p>
            </body></html>""", 401
        return """<!DOCTYPE html><html><head><title>CorpNet Internal Portal</title>
        <style>body{background:#0d1117;color:#58a6ff;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
        .box{background:#161b22;padding:40px;border-radius:8px;border:1px solid #30363d;width:320px;}
        h2{color:#f0f6fc;margin-bottom:24px;}input{width:100%;padding:10px;margin:8px 0;background:#0d1117;border:1px solid #30363d;color:#f0f6fc;border-radius:4px;}
        button{width:100%;padding:12px;background:#238636;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px;}
        .logo{color:#ff4444;font-size:12px;margin-bottom:16px;}
        </style></head><body><div class='box'>
        <div class='logo'>🔒 CORPNET SECURE INTRANET v3.2.1</div>
        <h2>Employee Login</h2>
        <form method='POST'><input type='text' name='username' placeholder='Username'/>
        <input type='password' name='password' placeholder='Password'/>
        <button type='submit'>Sign In</button></form>
        <p style='font-size:11px;color:#8b949e;margin-top:16px;'>Authorized personnel only. All access is monitored.</p>
        </div></body></html>"""

    @hp.route("/admin", methods=["GET", "POST"])
    def admin():
        t.sleep(random.uniform(0.2, 0.7))
        data = request.get_data(as_text=True)
        _log_and_report(request.remote_addr, "ADMIN_PANEL", data or "/admin accessed", request.headers)
        return """<!DOCTYPE html><html><head><title>Admin Panel — CorpNet</title>
        <style>body{background:#111;color:#0f0;font-family:monospace;padding:20px;}
        table{border-collapse:collapse;width:100%;}td,th{border:1px solid #333;padding:8px;}
        .warn{color:#ff0;}</style></head><body>
        <h1 style='color:#f00;'>⚠ ADMIN CONTROL PANEL</h1>
        <p class='warn'>WARNING: Restricted Area — Unauthorized access prohibited</p>
        <h3>System Status</h3>
        <table><tr><th>Service</th><th>Status</th><th>Uptime</th></tr>
        <tr><td>Database</td><td style='color:#0f0;'>ONLINE</td><td>99.98%</td></tr>
        <tr><td>Auth Server</td><td style='color:#0f0;'>ONLINE</td><td>99.95%</td></tr>
        <tr><td>Backup Server</td><td style='color:#ff0;'>DEGRADED</td><td>87.2%</td></tr>
        </table>
        <h3>Recent Logins</h3>
        <table><tr><th>User</th><th>IP</th><th>Time</th></tr>
        <tr><td>admin</td><td>192.168.1.1</td><td>2 min ago</td></tr>
        <tr><td>jsmith</td><td>192.168.1.45</td><td>15 min ago</td></tr>
        </table></body></html>"""

    @hp.route("/api/users", methods=["GET"])
    def api_users():
        t.sleep(random.uniform(0.1, 0.4))
        _log_and_report(request.remote_addr, "API_USERS", "/api/users", request.headers)
        return jsonify({
            "status": "ok",
            "users": [
                {"id": 1, "name": "John Smith", "role": "CEO", "email": "jsmith@corp.internal", "clearance": "TOP_SECRET"},
                {"id": 2, "name": "Sarah Connor", "role": "CTO", "email": "sconnor@corp.internal", "clearance": "SECRET"},
                {"id": 3, "name": "Mike Davis", "role": "DBA", "email": "mdavis@corp.internal", "clearance": "CONFIDENTIAL"},
                {"id": 4, "name": "Lisa Park", "role": "DevOps", "email": "lpark@corp.internal", "clearance": "INTERNAL"},
                {"id": 5, "name": "Tom Wilson", "role": "Analyst", "email": "twilson@corp.internal", "clearance": "INTERNAL"},
            ],
            "total": 5,
            "db_version": "PostgreSQL 14.2",
            "_internal_note": "PROD DB — Employee records — DO NOT DISTRIBUTE",
        })

    @hp.route("/api/data", methods=["GET", "POST"])
    def api_data():
        t.sleep(random.uniform(0.2, 0.6))
        data = request.get_data(as_text=True)
        _log_and_report(request.remote_addr, "API_DATA", data or "GET /api/data", request.headers)
        # Check for SQL injection patterns
        if SQL_PATTERNS.search(data) or SQL_PATTERNS.search(request.query_string.decode()):
            return jsonify({
                "error": "SQL syntax error near unexpected token",
                "db": "PostgreSQL 14.2",
                "query": data[:100],
                "stacktrace": "PG::SyntaxError: ERROR: syntax error at or near \"'\"",
            }), 500
        return jsonify({
            "status": "ok",
            "records": 15482,
            "last_backup": "2024-01-15T03:00:00Z",
            "data": [{"id": i, "value": f"CONFIDENTIAL_RECORD_{i}"} for i in range(1, 11)],
        })

    @hp.route("/backup", methods=["GET"])
    def backup():
        t.sleep(random.uniform(0.4, 1.0))
        _log_and_report(request.remote_addr, "BACKUP_ACCESS", "/backup", request.headers)
        return jsonify({
            "files": [
                "backup_employee_records_2024.sql.gz",
                "backup_financials_Q4_2024.tar.gz",
                "backup_credentials_vault.enc",
                "system_backup_20240115.tar",
            ],
            "location": "/var/backup/",
            "size_gb": 84.3,
        })

    @hp.route("/dashboard", methods=["GET"])
    def dashboard():
        t.sleep(random.uniform(0.2, 0.5))
        _log_and_report(request.remote_addr, "DASHBOARD", "/dashboard", request.headers)
        return """<!DOCTYPE html><html><head><title>CorpNet Dashboard</title></head>
        <body style='background:#1a1a2e;color:#eee;font-family:monospace;padding:20px;'>
        <h1>📊 CorpNet Internal Dashboard</h1>
        <p>Welcome back. Last login: 2 hours ago from 192.168.1.45</p>
        <div style='background:#16213e;padding:20px;border-radius:8px;margin:20px 0;'>
        <h3>🔴 CLASSIFIED MEMO</h3>
        <p>Q4 financial results ahead of schedule. Server migration to AWS planned for next month.
        Credentials rotation scheduled — see IT for new vault passphrase.</p></div>
        </body></html>"""

    # Catch-all for directory traversal and unknown paths
    @hp.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def catch_all(path):
        t.sleep(random.uniform(0.1, 0.5))
        data = request.get_data(as_text=True)
        full = f"/{path}?{request.query_string.decode()}"
        _log_and_report(request.remote_addr, "DIR_TRAVERSAL" if ".." in path else "PROBE", full, request.headers)
        if ".." in path or "etc/passwd" in path:
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
corpnet:x:1000:1000:CorpNet Admin:/home/corpnet:/bin/bash
""", 200
        return "404 Not Found", 404

    hp.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


# ─── Simulation Engine ───────────────────────────────────────────────────────
FAKE_IPS = [
    "185.220.101.47",
    "45.142.212.100",
    "192.168.1.200",
    "10.0.0.254",
    "78.47.139.201",
]

SIMULATION_SEQUENCE = [
    ("PORT_SCAN", "ALL SERVICES", "HIGH", "Ports: [22, 80, 443, 3306, 8080, 8443]", 2.0),
    ("NMAP_SCAN", "API SERVER", "HIGH", "Nmap 7.90 OS detection scan", 3.0),
    ("BRUTE_FORCE", "SSH (AUTH SERVER)", "CRITICAL", "SSH brute force — rockyou.txt", 4.0),
    ("SQL_INJECTION", "DATABASE", "CRITICAL", "' OR 1=1--; UNION SELECT * FROM users--", 3.5),
    ("DIR_TRAVERSAL", "API SERVER", "HIGH", "/../../../etc/passwd", 2.5),
    ("BRUTE_FORCE", "HTTP (API SERVER)", "HIGH", "HTTP form brute force — 500 attempts/min", 4.0),
]


async def run_simulation():
    """Fire simulated attack sequence for demo backup."""
    log.info("[SIM] Starting attack simulation sequence...")
    for attack_type, service, severity, payload, delay in SIMULATION_SEQUENCE:
        ip = random.choice(FAKE_IPS)
        await handle_attack(ip, attack_type, service, severity, payload)
        await asyncio.sleep(delay)
    log.info("[SIM] Simulation complete.")


# ─── Honeypot Data Receiver ──────────────────────────────────────────────────
async def process_honeypot_data(data: dict):
    """Handle incoming honeypot data from the dedicated honeypot server."""
    source_ip = data.get("source_ip", "unknown")
    service = data.get("service", "UNKNOWN")
    payload = data.get("payload", "")
    tool = data.get("tool_detected", "Unknown")
    headers = data.get("headers", "")

    db_log_honeypot(source_ip, service, payload, tool, str(headers))

    # Build attacker profile
    score = min(100, state.attacker_profile.get("threat_score", 0) + random.randint(8, 18))
    state.attacker_profile["threat_score"] = score
    state.attacker_profile["ip"] = source_ip
    tools_set = state.attacker_profile.get("tools", set())
    if isinstance(tools_set, list):
        tools_set = set(tools_set)
    tools_set.add(tool)
    state.attacker_profile["tools"] = tools_set
    svcs = state.attacker_profile.get("services_hit", [])
    if service not in svcs:
        svcs.append(service)
    state.attacker_profile["services_hit"] = svcs
    cmds = state.attacker_profile.get("commands", [])
    if payload and payload not in cmds:
        cmds.append(payload[:100])
    state.attacker_profile["commands"] = cmds

    await manager.broadcast({
        "type": "honeypot",
        "data": {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "service": service,
            "payload": payload[:300],
            "tool_detected": tool,
            "intel_update": {
                "ip": source_ip,
                "tools": list(tools_set),
                "services_hit": svcs,
                "threat_score": score,
                "command": payload[:100] if payload else None,
                "headers": str(headers)[:200],
            },
        },
    })


# ─── Lifespan / Startup ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()
    init_db()
    log.info(f"[SENTINEL] Local IP detected: {LOCAL_IP}")
    # Start Scapy sniffer in background thread (needs root/admin)
    t = threading.Thread(target=start_scapy_sniffer, daemon=True)
    t.start()
    log.info("[SENTINEL] Core online. Monitoring network traffic.")
    yield
    log.info("[SENTINEL] Shutting down.")


# ─── FastAPI App ──────────────────────────────────────────────────────────────
app = FastAPI(title="SENTINEL Core", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def health():
    return {
        "status": "ONLINE",
        "system": "SENTINEL Core v1.0",
        "local_ip": LOCAL_IP,
        "stats": {
            "attacks_detected": state.attacks_detected,
            "attacks_blocked": state.attacks_blocked,
            "active_threats": state.active_threats,
        },
        "honeypot_active": state.honeypot_active,
    }


@app.post("/simulate")
async def simulate():
    asyncio.create_task(run_simulation())
    return {"status": "simulation_started", "message": "Attack simulation sequence initiated"}


@app.post("/honeypot/engage")
async def engage_honeypot():
    global honeypot_thread
    if state.honeypot_active:
        return {"status": "already_active", "port": state.honeypot_port}

    state.honeypot_active = True
    honeypot_thread = threading.Thread(
        target=start_honeypot_server,
        args=(state.honeypot_port,),
        daemon=True,
    )
    honeypot_thread.start()

    # Notify dashboard
    await manager.broadcast({
        "type": "defense",
        "data": {
            "timestamp": datetime.utcnow().isoformat(),
            "action": "HONEYPOT DEPLOYED",
            "message": f"Decoy infrastructure active on port {state.honeypot_port}. Attacker is now being trapped.",
            "service_protected": "ALL SERVICES",
            "ai_analysis": "Honeypot engaged — attacker redirected to controlled decoy environment for intelligence gathering.",
            "stats": {
                "attacks_detected": state.attacks_detected,
                "attacks_blocked": state.attacks_blocked,
                "active_threats": state.active_threats,
            },
        },
    })
    return {"status": "honeypot_engaged", "port": state.honeypot_port}


@app.post("/honeypot/data")
async def honeypot_data(data: dict):
    """Receive intelligence from dedicated honeypot server."""
    await process_honeypot_data(data)
    return {"status": "received"}


@app.get("/logs")
async def get_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 100")
    attacks = c.fetchall()
    c.execute("SELECT * FROM honeypot_logs ORDER BY id DESC LIMIT 100")
    honeypot = c.fetchall()
    conn.close()
    return {
        "attack_logs": [
            {
                "id": r[0], "timestamp": r[1], "attack_type": r[2],
                "source_ip": r[3], "target_service": r[4], "severity": r[5],
                "payload": r[6], "blocked": bool(r[7]), "ai_analysis": r[8],
            }
            for r in attacks
        ],
        "honeypot_logs": [
            {
                "id": r[0], "timestamp": r[1], "source_ip": r[2],
                "service": r[3], "payload": r[4], "tool_detected": r[5], "headers": r[6],
            }
            for r in honeypot
        ],
    }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    # Send current state to newly connected dashboard
    await ws.send_json({
        "type": "init",
        "data": {
            "stats": {
                "attacks_detected": state.attacks_detected,
                "attacks_blocked": state.attacks_blocked,
                "active_threats": state.active_threats,
            },
            "honeypot_active": state.honeypot_active,
            "blocked_ips": list(state.blocked_ips),
        },
    })
    try:
        while True:
            # Keep connection alive
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
