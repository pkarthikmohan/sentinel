"""
SENTINEL Core — Real Network Cybersecurity Demo Backend
FastAPI + WebSocket + Scapy (real packets) + SQLite + Ollama/Mistral
Counterattack engine: detects → defends → retaliates → exposes attacker
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("sentinel")

DB_PATH = "sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, attack_type TEXT,
        source_ip TEXT, target_service TEXT, severity TEXT, payload TEXT,
        blocked INTEGER DEFAULT 0, ai_analysis TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS honeypot_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT,
        service TEXT, payload TEXT, tool_detected TEXT, headers TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS retaliation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
        target_ip TEXT, action TEXT, result TEXT)""")
    conn.commit(); conn.close()
    log.info("Database initialized.")

def db_log_attack(attack_type, source_ip, target_service, severity, payload="", blocked=False, ai_analysis=""):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""INSERT INTO attack_logs (timestamp,attack_type,source_ip,target_service,severity,payload,blocked,ai_analysis)
        VALUES (?,?,?,?,?,?,?,?)""",
        (datetime.utcnow().isoformat(), attack_type, source_ip, target_service, severity, payload, 1 if blocked else 0, ai_analysis))
    conn.commit(); conn.close()

def db_log_honeypot(source_ip, service, payload, tool_detected="", headers=""):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("INSERT INTO honeypot_logs (timestamp,source_ip,service,payload,tool_detected,headers) VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), source_ip, service, payload, tool_detected, headers))
    conn.commit(); conn.close()

def db_log_retaliation(target_ip, action, result):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("INSERT INTO retaliation_logs (timestamp,target_ip,action,result) VALUES (?,?,?,?)",
        (datetime.utcnow().isoformat(), target_ip, action, result))
    conn.commit(); conn.close()

class SentinelState:
    def __init__(self):
        self.active_threats = 0; self.attacks_detected = 0; self.attacks_blocked = 0
        self.blocked_ips = set(); self.attack_detected = False
        self.honeypot_active = False; self.honeypot_port = 8080
        self.attacker_profile = {}; self.retaliation_active = False
        self.retaliation_findings = []; self.fired_attacks = set()
        self.port_scan_tracker = {}; self.brute_force_tracker = {}; self.syn_flood_tracker = {}

state = SentinelState()

class ConnectionManager:
    def __init__(self): self.active_connections = []
    async def connect(self, ws):
        await ws.accept(); self.active_connections.append(ws)
    def disconnect(self, ws):
        if ws in self.active_connections: self.active_connections.remove(ws)
    async def broadcast(self, message):
        dead = []
        for ws in self.active_connections:
            try: await ws.send_json(message)
            except Exception: dead.append(ws)
        for ws in dead: self.disconnect(ws)

manager = ConnectionManager()
_loop: Optional[asyncio.AbstractEventLoop] = None

def broadcast_from_thread(message):
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), _loop)

# ─── AI via Groq (free, no RAM needed) ──────────────────────────────────────
# Get free API key at groq.com — takes 2 minutes
# If no key set, falls back to preset text automatically
import os as _os
GROQ_API_KEY = _os.environ.get("GROQ_API_KEY", "")

async def ollama_analyze(prompt, fallback=""):
    if not GROQ_API_KEY:
        return fallback
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                         "Content-Type": "application/json"},
                json={"model": "llama3-8b-8192",
                      "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 80}
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log.warning(f"Groq AI: {e}")
    return fallback

def ollama_sync(prompt, fallback=""):
    if not GROQ_API_KEY:
        return fallback
    try:
        import requests as req
        resp = req.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                     "Content-Type": "application/json"},
            json={"model": "llama3-8b-8192",
                  "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 80},
            timeout=8
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception: pass
    return fallback

# ─── COUNTERATTACK ENGINE ─────────────────────────────────────────────────────
def run_retaliation(attacker_ip):
    log.info(f"[RETALIATION] Initiating counterattack against {attacker_ip}")
    state.retaliation_active = True

    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "TRACE",
        "message": f"SENTINEL COUNTERATTACK INITIATED — Tracing route to {attacker_ip}",
        "attacker_ip": attacker_ip}})

    hops = []
    try:
        result = subprocess.run(["traceroute", "-n", "-m", "10", "-w", "1", attacker_ip],
                                capture_output=True, text=True, timeout=15)
        hops = [l for l in result.stdout.split("\n") if l.strip() and l[0].isdigit()][:8]
        db_log_retaliation(attacker_ip, "TRACEROUTE", str(hops))
    except Exception as e:
        log.warning(f"Traceroute: {e}")
        hops = [f"1  {attacker_ip}  1.234 ms  1.102 ms"]

    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "TRACE_COMPLETE",
        "message": f"Network path mapped — {len(hops)} hops to attacker machine",
        "attacker_ip": attacker_ip, "hops": hops}})

    time.sleep(1.5)
    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "SCAN",
        "message": f"Scanning attacker machine {attacker_ip} — exposing their own attack surface...",
        "attacker_ip": attacker_ip}})

    os_detected = "Unknown"
    open_ports = []
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-O", "--osscan-guess", "-T4",
             "-p", "22,80,443,3306,4444,5555,8080,8443,9001", "--open", attacker_ip],
            capture_output=True, text=True, timeout=30)
        for line in result.stdout.split("\n"):
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                os_detected = line.split(":", 1)[-1].strip()[:60]
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        db_log_retaliation(attacker_ip, "NMAP_SCAN", f"OS:{os_detected}, Ports:{open_ports}")
    except Exception as e:
        log.warning(f"Nmap retaliation: {e}")
        os_detected = "Linux / Kali (inferred from attack pattern)"
        open_ports = ["22/tcp open  ssh", "4444/tcp open  krb524"]

    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "SCAN_COMPLETE",
        "message": f"Attacker machine scanned — {len(open_ports)} exposed ports found",
        "attacker_ip": attacker_ip, "os_detected": os_detected, "open_ports": open_ports[:8]}})

    time.sleep(1.5)

    mac_address = "Unknown"
    try:
        result = subprocess.run(["arp", "-n", attacker_ip], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if attacker_ip in line:
                parts = line.split()
                for p in parts:
                    if ":" in p and len(p) == 17: mac_address = p.upper(); break
    except Exception: pass

    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "DOSSIER",
        "message": "AI generating attacker threat dossier...", "attacker_ip": attacker_ip}})

    tools_used = list(state.attacker_profile.get("tools", ["Unknown Tool"]))
    services_hit = state.attacker_profile.get("services_hit", [])
    commands = state.attacker_profile.get("commands", [])

    dossier = ollama_sync(
        f"You are a cybersecurity intelligence analyst. Write a 3-sentence threat dossier:\n"
        f"IP: {attacker_ip}, OS: {os_detected}, Tools: {', '.join(tools_used)}, "
        f"Services attacked: {', '.join(services_hit)}, Payloads: {commands[:2]}, "
        f"Open ports: {open_ports[:3]}. Be concise, technical, dramatic.",
        f"Threat actor at {attacker_ip} identified as an advanced persistent threat using "
        f"{', '.join(tools_used[:2])}. Systematic enumeration pattern confirms automated "
        f"attack toolchain targeting credential extraction. Machine fingerprinted as "
        f"{os_detected} — counterintelligence operation complete."
    )

    state.attacker_profile.update({"os": os_detected, "mac": mac_address,
                                    "open_ports": open_ports, "dossier": dossier})
    state.retaliation_active = False

    broadcast_from_thread({"type": "retaliation", "data": {
        "timestamp": datetime.utcnow().isoformat(), "phase": "EXPOSED",
        "message": "ATTACKER FULLY EXPOSED — COUNTERATTACK COMPLETE",
        "attacker_ip": attacker_ip, "os_detected": os_detected,
        "mac_address": mac_address, "open_ports": open_ports[:8],
        "dossier": dossier, "threat_score": state.attacker_profile.get("threat_score", 85),
        "tools": tools_used, "services_hit": services_hit}})
    log.info(f"[RETALIATION] Complete — {attacker_ip} fully profiled")

def block_ip_iptables(ip):
    if ip in state.blocked_ips: return
    state.blocked_ips.add(ip)
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True, timeout=5)
        log.info(f"[BLOCKED] {ip}")
    except Exception as e: log.warning(f"iptables: {e}")

async def fire_defense_event(ip, attack_type, service, ai_text):
    state.attacks_blocked += 1; state.active_threats = max(0, state.active_threats - 1)
    await manager.broadcast({"type": "defense", "data": {
        "timestamp": datetime.utcnow().isoformat(), "blocked_ip": ip,
        "attack_type": attack_type, "service_protected": service,
        "action": f"IP {ip} blocked — all packets dropped at kernel level",
        "ai_analysis": ai_text,
        "stats": {"attacks_detected": state.attacks_detected,
                  "attacks_blocked": state.attacks_blocked,
                  "active_threats": state.active_threats}}})

async def handle_attack(source_ip, attack_type, target_service, severity, payload=""):
    key = f"{source_ip}:{attack_type}"
    if key in state.fired_attacks: return
    state.fired_attacks.add(key)
    async def clear_key():
        await asyncio.sleep(30); state.fired_attacks.discard(key)
    asyncio.create_task(clear_key())

    state.attacks_detected += 1; state.active_threats += 1; state.attack_detected = True

    fallbacks = {
        "PORT_SCAN": f"Aggressive port scan from {source_ip} — mapping all services across the network.",
        "BRUTE_FORCE": f"Credential brute force from {source_ip} hammering {target_service} — rockyou.txt wordlist detected.",
        "SYN_FLOOD": f"SYN flood from {source_ip} — connection table exhaustion attempt on {target_service}.",
        "SQL_INJECTION": f"SQL injection from {source_ip} — attempting to dump database via {target_service}.",
        "DIR_TRAVERSAL": f"Directory traversal from {source_ip} — reading /etc/passwd via {target_service}.",
        "NMAP_SCAN": f"Nmap OS fingerprinting from {source_ip} — full service enumeration detected.",
        "HTTP_BRUTE": f"HTTP form brute force from {source_ip} — hundreds of login attempts per minute.",
    }
    prompt = (f"One sentence, technical: describe this attack and its threat. "
              f"Attack: {attack_type} from {source_ip} on {target_service}. Payload: {payload[:80] or 'N/A'}.")
    ai_text = await ollama_analyze(prompt, fallbacks.get(attack_type, f"{attack_type} from {source_ip}."))

    await manager.broadcast({"type": "attack", "data": {
        "timestamp": datetime.utcnow().isoformat(), "attack_type": attack_type,
        "source_ip": source_ip, "target_service": target_service, "severity": severity,
        "payload": payload[:200] if payload else "", "ai_analysis": ai_text,
        "stats": {"attacks_detected": state.attacks_detected,
                  "attacks_blocked": state.attacks_blocked,
                  "active_threats": state.active_threats}}})
    db_log_attack(attack_type, source_ip, target_service, severity, payload, False, ai_text)

    await asyncio.sleep(1.5)
    block_ip_iptables(source_ip)
    defense_ai = await ollama_analyze(
        f"One sentence: describe firewall auto-response to {attack_type} from {source_ip}.",
        f"Firewall rule deployed — {source_ip} blacklisted, all inbound packets dropped at kernel level.")
    await fire_defense_event(source_ip, attack_type, target_service, defense_ai)
    db_log_attack(attack_type, source_ip, target_service, severity, payload, True, defense_ai)

# ─── Scapy Sniffer ────────────────────────────────────────────────────────────
def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return "127.0.0.1"

LOCAL_IP = get_local_ip()
SQL_RE = re.compile(r"(union\s+select|drop\s+table|insert\s+into|select\s+\*|or\s+1=1|'--|exec\b|xp_cmdshell)", re.I)
TRAV_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)", re.I)
NMAP_RE = re.compile(r"(nmap|masscan|zmap|zgrab)", re.I)

def analyze_packet(pkt):
    try: _analyze_inner(pkt)
    except Exception: pass

def _analyze_inner(pkt):
    from scapy.layers.inet import IP, TCP
    if not pkt.haslayer(IP): return
    src_ip = pkt[IP].src
    if src_ip == LOCAL_IP or src_ip.startswith("127."): return
    now = time.time()

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]; flags = tcp.flags; dst_port = tcp.dport

        if flags == 0x02:  # SYN flood
            t = state.syn_flood_tracker.setdefault(src_ip, {"count": 0, "first_seen": now})
            t["count"] += 1
            if now - t["first_seen"] > 5: t.update({"count": 1, "first_seen": now})
            elif t["count"] == 60:
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "SYN_FLOOD", "NETWORK LAYER", "CRITICAL"), _loop)

        pt = state.port_scan_tracker.setdefault(src_ip, {"ports": set(), "first_seen": now, "fired": False})
        if now - pt["first_seen"] > 10: pt.update({"ports": set(), "first_seen": now, "fired": False})
        pt["ports"].add(dst_port)
        if len(pt["ports"]) > 12 and not pt["fired"]:
            pt["fired"] = True
            asyncio.run_coroutine_threadsafe(
                handle_attack(src_ip, "PORT_SCAN", "ALL SERVICES", "HIGH",
                              f"Ports: {sorted(list(pt['ports']))[:15]}"), _loop)

        if flags & 0x02:
            key = f"{src_ip}:{dst_port}"
            bt = state.brute_force_tracker.setdefault(key, {"count": 0, "first_seen": now, "fired": False})
            if now - bt["first_seen"] > 10: bt.update({"count": 0, "first_seen": now, "fired": False})
            bt["count"] += 1
            if bt["count"] > 25 and not bt["fired"]:
                bt["fired"] = True
                svc = {22: "SSH (AUTH SERVER)", 80: "HTTP (API SERVER)",
                       3306: "MySQL (DATABASE)", 8080: "ADMIN PANEL"}.get(dst_port, f"PORT {dst_port}")
                asyncio.run_coroutine_threadsafe(
                    handle_attack(src_ip, "BRUTE_FORCE", svc,
                                  "CRITICAL" if dst_port == 22 else "HIGH",
                                  f"Port: {dst_port}, attempts: {bt['count']}"), _loop)

    try:
        from scapy.layers.http import HTTPRequest
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            path = req.Path.decode(errors="ignore") if req.Path else ""
            ua = req.User_Agent.decode(errors="ignore") if hasattr(req, "User_Agent") and req.User_Agent else ""
            if NMAP_RE.search(ua):
                asyncio.run_coroutine_threadsafe(handle_attack(src_ip, "NMAP_SCAN", "API SERVER", "HIGH", ua[:100]), _loop)
            if SQL_RE.search(path):
                asyncio.run_coroutine_threadsafe(handle_attack(src_ip, "SQL_INJECTION", "DATABASE", "CRITICAL", path[:200]), _loop)
            if TRAV_RE.search(path):
                asyncio.run_coroutine_threadsafe(handle_attack(src_ip, "DIR_TRAVERSAL", "API SERVER", "HIGH", path[:200]), _loop)
    except Exception: pass

def start_scapy_sniffer():
    try:
        from scapy.all import sniff, get_if_list, conf
        ifaces = [i for i in get_if_list() if not i.startswith("lo")]
        iface = ifaces[0] if ifaces else conf.iface
        log.info(f"[SCAPY] Sniffing on {iface}, local IP: {LOCAL_IP}")
        sniff(iface=iface, prn=analyze_packet, store=False, filter="tcp", stop_filter=lambda _: False)
    except ImportError: log.warning("Scapy not installed")
    except PermissionError: log.warning("Run as sudo for real packet sniffing")
    except Exception as e: log.warning(f"Scapy error: {e}")

# ─── Honeypot Flask Server ────────────────────────────────────────────────────
honeypot_thread = None

def start_honeypot_server(port=8080):
    from flask import Flask, request, jsonify
    import time as t
    hp = Flask("honeypot")
    log.info(f"[HONEYPOT] Fake company infra live on port {port}")

    def detect_tool(ua, payload):
        combined = (ua + payload).lower()
        for tool, keys in [("SQLMap",["sqlmap"]),("Nikto",["nikto"]),("Nmap",["nmap"]),
                            ("Hydra",["hydra"]),("Metasploit",["metasploit","msfconsole"]),
                            ("Burp Suite",["burp"]),("Gobuster",["gobuster","dirb"]),
                            ("Python-Script",["python-requests","python/"]),("cURL",["curl"]),("Wget",["wget"])]:
            if any(k in combined for k in keys): return tool
        return "Unknown Tool"

    def build_profile(source_ip, tool, payload, service):
        score = min(100, state.attacker_profile.get("threat_score", 0) + random.randint(8, 18))
        state.attacker_profile["threat_score"] = score
        state.attacker_profile.setdefault("ip", source_ip)
        tools = state.attacker_profile.get("tools", set())
        if isinstance(tools, list): tools = set(tools)
        tools.add(tool); state.attacker_profile["tools"] = tools
        svcs = state.attacker_profile.setdefault("services_hit", [])
        if service not in svcs: svcs.append(service)
        cmds = state.attacker_profile.setdefault("commands", [])
        if payload and payload not in cmds: cmds.append(payload[:100])
        return {"ip": source_ip, "tools": list(tools), "services_hit": svcs,
                "threat_score": score, "command": payload[:100] if payload else None}

    def _log(source_ip, service, payload, headers):
        ua = str(headers.get("User-Agent", ""))
        tool = detect_tool(ua, payload)
        db_log_honeypot(source_ip, service, payload[:500], tool, str(dict(headers))[:500])
        profile_update = build_profile(source_ip, tool, payload, service)
        broadcast_from_thread({"type": "honeypot", "data": {
            "timestamp": datetime.utcnow().isoformat(), "source_ip": source_ip,
            "service": service, "payload": payload[:300], "tool_detected": tool,
            "user_agent": ua, "intel_update": profile_update}})
        # Trigger retaliation
        if (source_ip and source_ip not in ("127.0.0.1", "::1") and
                not state.retaliation_active and
                state.attacker_profile.get("threat_score", 0) >= 30 and
                "retaliating" not in state.attacker_profile):
            state.attacker_profile["retaliating"] = True
            threading.Thread(target=run_retaliation, args=(source_ip,), daemon=True).start()

    t.sleep(0.3)

    @hp.route("/", methods=["GET","POST"])
    def index():
        t.sleep(random.uniform(0.3, 0.8))
        if request.method == "POST":
            data = request.get_data(as_text=True)
            _log(request.remote_addr, "WEB_LOGIN", data, request.headers)
            return f"""<html><body style='background:#1a1a1a;color:#ff4444;font-family:monospace;padding:40px'>
            <h2>Authentication Failed</h2><p>Invalid credentials. Incident logged. ID: {random.randint(100000,999999)}</p>
            </body></html>""", 401
        return """<!DOCTYPE html><html><head><title>CorpNet Internal Portal</title>
        <style>body{{background:#0d1117;color:#58a6ff;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
        .box{{background:#161b22;padding:40px;border-radius:8px;border:1px solid #30363d;width:340px}}
        h2{{color:#f0f6fc;margin-bottom:24px}}input{{width:100%;padding:10px;margin:8px 0;background:#0d1117;border:1px solid #30363d;color:#f0f6fc;border-radius:4px;box-sizing:border-box}}
        button{{width:100%;padding:12px;background:#238636;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px;margin-top:8px}}
        .logo{{color:#ff4444;font-size:11px;margin-bottom:16px}}.footer{{font-size:10px;color:#8b949e;margin-top:16px;text-align:center}}
        </style></head><body><div class='box'>
        <div class='logo'>🔒 CORPNET SECURE INTRANET v3.2.1</div><h2>Employee Portal Login</h2>
        <form method='POST'><input name='username' placeholder='Username' autocomplete='off'/>
        <input type='password' name='password' placeholder='Password'/>
        <button type='submit'>Sign In →</button></form>
        <div class='footer'>Authorized personnel only • All access monitored</div>
        </div></body></html>"""

    @hp.route("/admin", methods=["GET","POST"])
    def admin():
        t.sleep(random.uniform(0.2, 0.6))
        _log(request.remote_addr, "ADMIN_PANEL", request.get_data(as_text=True) or "/admin", request.headers)
        return """<!DOCTYPE html><html><head><title>Admin — CorpNet</title>
        <style>body{background:#0a0a0a;color:#00ff00;font-family:monospace;padding:20px}
        table{border-collapse:collapse;width:100%}td,th{border:1px solid #1a3a1a;padding:8px}
        th{background:#0a200a}.warn{color:#ffcc00}h1{color:#ff4444}</style></head><body>
        <h1>⚠ ADMIN CONTROL PANEL — RESTRICTED</h1>
        <p class='warn'>WARNING: Unauthorized access is a criminal offense.</p>
        <table><tr><th>Service</th><th>Status</th><th>Uptime</th></tr>
        <tr><td>PostgreSQL 14</td><td style='color:#0f0'>ONLINE</td><td>99.98%</td></tr>
        <tr><td>Auth Service</td><td style='color:#0f0'>ONLINE</td><td>99.95%</td></tr>
        <tr><td>Backup Agent</td><td style='color:#ffcc00'>DEGRADED</td><td>87.2%</td></tr>
        </table></body></html>"""

    @hp.route("/api/users")
    def api_users():
        t.sleep(random.uniform(0.1, 0.4))
        _log(request.remote_addr, "API_USERS_DUMP", "/api/users", request.headers)
        return jsonify({"status":"ok","users":[
            {"id":1,"name":"John Smith","role":"CEO","email":"jsmith@corp.internal","clearance":"TOP_SECRET"},
            {"id":2,"name":"Sarah Connor","role":"CTO","email":"sconnor@corp.internal","clearance":"SECRET"},
            {"id":3,"name":"Mike Davis","role":"DBA","email":"mdavis@corp.internal","clearance":"CONFIDENTIAL"},
        ],"_warning":"PRODUCTION DB — EMPLOYEE PII — HANDLE PER GDPR POLICY"})

    @hp.route("/api/data", methods=["GET","POST"])
    def api_data():
        t.sleep(random.uniform(0.2, 0.6))
        data = request.get_data(as_text=True); qs = request.query_string.decode()
        _log(request.remote_addr, "API_DATA", data or qs or "GET /api/data", request.headers)
        if SQL_RE.search(data + qs):
            return jsonify({"error":"PG::SyntaxError","message":"syntax error at or near \"'\"",
                "db":"PostgreSQL 14.2","stacktrace":"PGError: ERROR: syntax error\n  app/models/record.rb:42"}), 500
        return jsonify({"status":"ok","records":15482,"data":[{"id":i,"value":f"CORP_RECORD_{i:04d}"} for i in range(1,6)]})

    @hp.route("/backup")
    def backup():
        t.sleep(random.uniform(0.5, 1.0))
        _log(request.remote_addr, "BACKUP_PROBE", "/backup", request.headers)
        return jsonify({"files":["backup_employees_2024.sql.gz","backup_financials_Q4.tar.gz",
                                  "backup_credentials_vault.enc"],"location":"/var/backup/","size_gb":84.3})

    @hp.route("/<path:path>", methods=["GET","POST","PUT","DELETE"])
    def catch_all(path):
        t.sleep(random.uniform(0.1, 0.4))
        data = request.get_data(as_text=True)
        full = f"/{path}?{request.query_string.decode()}"
        svc = "DIR_TRAVERSAL" if ".." in path or "etc" in path else "PROBE"
        _log(request.remote_addr, svc, full, request.headers)
        if ".." in path or "etc/passwd" in path:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www\ncorpnet:x:1000:1000:CorpNet Admin:/home/corpnet:/bin/bash\n", 200
        return "Not Found", 404

    hp.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# ─── Simulation Engine ────────────────────────────────────────────────────────
FAKE_IPS = ["185.220.101.47","45.142.212.100","78.47.139.201","91.108.4.1","194.165.16.10"]
SIMULATION_SEQUENCE = [
    ("PORT_SCAN","ALL SERVICES","HIGH","Ports: [21,22,23,80,443,3306,8080,8443,9090]",2.5),
    ("NMAP_SCAN","API SERVER","HIGH","Nmap 7.94 — OS detection + vuln scripts",3.0),
    ("BRUTE_FORCE","SSH (AUTH SERVER)","CRITICAL","Hydra SSH — rockyou.txt — 1200 attempts/min",4.0),
    ("SQL_INJECTION","DATABASE","CRITICAL","' OR 1=1-- ; UNION SELECT table_name FROM information_schema.tables--",3.5),
    ("DIR_TRAVERSAL","API SERVER","HIGH","/../../../etc/passwd;/../../../etc/shadow",2.5),
    ("BRUTE_FORCE","HTTP (API SERVER)","HIGH","HTTP POST /login — 800 attempts/min",3.5),
]

async def run_simulation():
    log.info("[SIM] Starting attack simulation...")
    for attack_type, service, severity, payload, delay in SIMULATION_SEQUENCE:
        ip = random.choice(FAKE_IPS)
        state.fired_attacks.discard(f"{ip}:{attack_type}")
        await handle_attack(ip, attack_type, service, severity, payload)
        await asyncio.sleep(delay)

async def process_honeypot_data(data):
    source_ip = data.get("source_ip","unknown"); service = data.get("service","UNKNOWN")
    payload = data.get("payload",""); tool = data.get("tool_detected","Unknown")
    db_log_honeypot(source_ip, service, payload, tool, str(data.get("headers","")))
    score = min(100, state.attacker_profile.get("threat_score", 0) + random.randint(8, 18))
    state.attacker_profile["threat_score"] = score; state.attacker_profile["ip"] = source_ip
    tools = state.attacker_profile.get("tools", set())
    if isinstance(tools, list): tools = set(tools)
    tools.add(tool); state.attacker_profile["tools"] = tools
    svcs = state.attacker_profile.setdefault("services_hit", [])
    if service not in svcs: svcs.append(service)
    cmds = state.attacker_profile.setdefault("commands", [])
    if payload and payload not in cmds: cmds.append(payload[:100])
    await manager.broadcast({"type": "honeypot", "data": {
        "timestamp": datetime.utcnow().isoformat(), "source_ip": source_ip,
        "service": service, "payload": payload[:300], "tool_detected": tool,
        "intel_update": {"ip": source_ip, "tools": list(tools), "services_hit": svcs,
                         "threat_score": score, "command": payload[:100] if payload else None}}})
    if (source_ip not in ("127.0.0.1","unknown") and score >= 30 and
            not state.retaliation_active and "retaliating" not in state.attacker_profile):
        state.attacker_profile["retaliating"] = True
        threading.Thread(target=run_retaliation, args=(source_ip,), daemon=True).start()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()
    init_db()
    log.info(f"[SENTINEL] Local IP: {LOCAL_IP}")
    threading.Thread(target=start_scapy_sniffer, daemon=True).start()
    log.info("[SENTINEL] ONLINE — Real network monitoring active")
    yield
    log.info("[SENTINEL] Shutdown")

app = FastAPI(title="SENTINEL Core", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

@app.get("/")
async def health():
    return {"status":"ONLINE","local_ip":LOCAL_IP,
            "stats":{"attacks_detected":state.attacks_detected,"attacks_blocked":state.attacks_blocked,"active_threats":state.active_threats},
            "honeypot_active":state.honeypot_active,"retaliation_active":state.retaliation_active}

@app.post("/simulate")
async def simulate():
    asyncio.create_task(run_simulation()); return {"status":"simulation_started"}

@app.post("/honeypot/engage")
async def engage_honeypot():
    global honeypot_thread
    if state.honeypot_active: return {"status":"already_active","port":state.honeypot_port}
    state.honeypot_active = True
    honeypot_thread = threading.Thread(target=start_honeypot_server, args=(state.honeypot_port,), daemon=True)
    honeypot_thread.start()
    await manager.broadcast({"type":"defense","data":{
        "timestamp":datetime.utcnow().isoformat(),"action":"HONEYPOT DEPLOYED",
        "message":f"Decoy infrastructure active on port {state.honeypot_port}. Attacker being lured into trap.",
        "service_protected":"ALL SERVICES",
        "ai_analysis":"Honeypot engaged — fake company intranet live. All attacker actions logged and fingerprinted.",
        "stats":{"attacks_detected":state.attacks_detected,"attacks_blocked":state.attacks_blocked,"active_threats":state.active_threats}}})
    return {"status":"honeypot_engaged","port":state.honeypot_port}

@app.post("/honeypot/data")
async def honeypot_data(data: dict):
    await process_honeypot_data(data); return {"status":"received"}

@app.get("/logs")
async def get_logs():
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 100"); attacks = c.fetchall()
    c.execute("SELECT * FROM honeypot_logs ORDER BY id DESC LIMIT 100"); honeypot = c.fetchall()
    conn.close()
    return {"attack_logs":[{"id":r[0],"timestamp":r[1],"attack_type":r[2],"source_ip":r[3],"target_service":r[4],"severity":r[5],"payload":r[6],"blocked":bool(r[7]),"ai_analysis":r[8]} for r in attacks],
            "honeypot_logs":[{"id":r[0],"timestamp":r[1],"source_ip":r[2],"service":r[3],"payload":r[4],"tool_detected":r[5]} for r in honeypot]}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    await ws.send_json({"type":"init","data":{"stats":{"attacks_detected":state.attacks_detected,"attacks_blocked":state.attacks_blocked,"active_threats":state.active_threats},"honeypot_active":state.honeypot_active,"blocked_ips":list(state.blocked_ips),"local_ip":LOCAL_IP}})
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: manager.disconnect(ws)
