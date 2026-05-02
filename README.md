# SENTINEL — Live Cybersecurity Demonstration System

A full-stack live cybersecurity demo built for hackathon stage presentations.

## System Architecture

```
sentinel-backend/     → Python FastAPI + WebSocket + Scapy + Ollama/Mistral
sentinel-dashboard/   → React + Vite (NASA control room UI)
sentinel-honeypot/    → Python fake company infrastructure (Web/SSH/MySQL)
sentinel-attacker/    → Kali Linux automated attack script
```

## Quick Start

### 1. Backend (run first)
```bash
cd sentinel-backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 2. Dashboard
```bash
cd sentinel-dashboard
npm install
npm start
# Opens at http://localhost:3000
```

### 3. Honeypot (on separate laptop)
```bash
cd sentinel-honeypot
pip install -r requirements.txt
python honeypot.py
```

### 4. Attacker Toolkit (on Kali Linux)
```bash
cd sentinel-attacker
python3 attack.py [TARGET_IP]
```

## Prerequisites
- Python 3.10+
- Node.js 18+
- [Ollama](https://ollama.com) with Mistral: `ollama pull mistral`
- Run backend as Administrator/root for Scapy packet sniffing

## Demo Flow
1. Start backend → Start dashboard → open http://localhost:3000
2. Click **SIMULATE ATTACK** to trigger the demo sequence
3. Watch Live Threat Feed populate with real-time attack events
4. Click **ENGAGE HONEYPOT** (appears after attack detected)
5. Watch Attacker Profile panel build the dossier in real time
