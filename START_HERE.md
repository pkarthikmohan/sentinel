# SENTINEL v2.0 — Complete Setup Guide
# READ THIS FIRST. Takes 10 minutes to set up.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## STEP 0 — NETWORK (do this before anything else)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. One person turns on mobile hotspot on their phone
2. ALL 4 laptops connect to that hotspot
3. On each laptop, find its IP: run `ip a` (Linux) or `ipconfig` (Windows)
   — look for 192.168.X.X

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## KALI VM — CRITICAL SETTING (do before anything)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Since you're using Kali as a VM, change ONE setting:

VirtualBox: Settings → Network → Adapter 1 → Attached to: BRIDGED ADAPTER
VMware:     Settings → Network Adapter → BRIDGED

Then inside Kali run: `ip a`
You should see a 192.168.X.X IP — different from your host laptop.
This means Kali is now visible to all other laptops on the network.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## FREE AI SETUP (optional but looks better)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Go to groq.com → sign up free → get API key
2. On Laptop 1 (SENTINEL), before running backend:
   export GROQ_API_KEY=your_key_here
   
If you skip this, the system uses preset analysis text — still looks great.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## LAPTOP 1 — SENTINEL BRAIN (project this on screen)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Terminal 1 — Backend:
  cd sentinel-backend
  pip install -r requirements.txt --break-system-packages
  sudo GROQ_API_KEY=your_key python3 -m uvicorn main:app --host 0.0.0.0 --port 8000

  ⚠ MUST run as sudo — needed for real packet sniffing

Terminal 2 — Dashboard:
  cd sentinel-dashboard
  npm install
  npm run dev
  
  Open browser: http://localhost:5173
  Fullscreen this — this is what gets projected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## LAPTOP 2 — HONEYPOT (the trap)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  cd sentinel-honeypot
  pip install -r requirements.txt --break-system-packages
  
  # Replace X.X with Laptop 1's actual IP
  sudo SENTINEL_URL=http://192.168.X.X:8000 python3 honeypot.py

  ⚠ sudo needed to bind port 22 (fake SSH) and port 80

  Your honeypot IP is what Kali will attack.
  Run `ip a` to find it — tell the Kali person this IP.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## LAPTOP 3 — KALI ATTACKER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Install everything (run once):
  sudo apt update
  sudo apt install -y nmap hydra sqlmap nikto gobuster dirb netcat-traditional curl wget traceroute arp-scan net-tools
  sudo gunzip /usr/share/wordlists/rockyou.txt.gz   (if not already done)
  pip3 install requests --break-system-packages

Run the attack (replace with Laptop 2's actual IP):
  cd sentinel-attacker
  sudo python3 attack.py 192.168.X.X

  ⚠ sudo needed for nmap SYN scan (-sS)
  ⚠ This is the laptop projected on a SECOND screen if possible
    so audience sees both: attack terminal + SENTINEL dashboard

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## DEMO FLOW ON STAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. All 3 services running (backend, honeypot, dashboard open)
2. Dashboard shows green — all calm
3. Kali person runs: sudo python3 attack.py 192.168.X.X
4. SENTINEL dashboard lights up — red, threat feed scrolling
5. After ~30 seconds — click ENGAGE HONEYPOT on dashboard
6. Kali's attack hits the honeypot — SENTINEL identifies tools live:
   SQLMap detected → Hydra detected → Nmap detected
7. Attacker profile builds in real time on right panel
8. COUNTERATTACK AUTO-FIRES — border turns purple:
   - SENTINEL traceroutes to Kali
   - Scans Kali's open ports
   - Captures Kali's MAC address
   - AI generates full threat dossier
9. Final screen: ATTACKER FULLY EXPOSED — red + purple
   Kali's real IP, OS, MAC, open ports, AI dossier — all on screen

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## IF SOMETHING BREAKS ON STAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dashboard has built-in demo mode — if backend is unreachable,
click SIMULATE ATTACK and ENGAGE HONEYPOT buttons.
Full sequence runs locally including fake retaliation.
Never fails. Always looks real.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## QUICK IP CHEAT SHEET (fill in before event)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Laptop 1 (SENTINEL brain):  192.168.___._____
Laptop 2 (Honeypot):        192.168.___._____
Laptop 3 (Kali attacker):   192.168.___._____
Hotspot phone IP:           192.168.___._____

