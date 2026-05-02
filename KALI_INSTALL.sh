#!/bin/bash
# Run this on Kali VM once — installs everything needed
# Usage: bash KALI_INSTALL.sh

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║  SENTINEL — Kali Attacker Setup Script    ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Update
echo "[1/5] Updating package list..."
sudo apt update -qq

# Install tools
echo "[2/5] Installing attack tools..."
sudo apt install -y \
  nmap \
  hydra \
  sqlmap \
  nikto \
  gobuster \
  dirb \
  netcat-traditional \
  curl \
  wget \
  traceroute \
  arp-scan \
  net-tools \
  python3 \
  python3-pip 2>/dev/null

# Python deps
echo "[3/5] Installing Python packages..."
pip3 install requests --break-system-packages -q

# Wordlist
echo "[4/5] Setting up wordlists..."
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
  sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
  echo "  rockyou.txt ready"
elif [ -f /usr/share/wordlists/rockyou.txt ]; then
  echo "  rockyou.txt already extracted"
else
  echo "  rockyou.txt not found — creating fallback list..."
  echo -e "password\n123456\nadmin\nroot\nqwerty\nletmein\npassword123\nadmin123\ncorpnet2024\nCorpNet!\nWelcome1\nP@ssw0rd\nSummer2024" > /tmp/quick_pass.txt
fi

# Verify
echo "[5/5] Verifying tools..."
for tool in nmap hydra sqlmap nikto gobuster curl; do
  if command -v $tool &>/dev/null; then
    echo "  ✓ $tool"
  else
    echo "  ✗ $tool — not found"
  fi
done

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║  Setup complete!                          ║"
echo "║                                           ║"
echo "║  IMPORTANT: Set VM to BRIDGED mode first  ║"
echo "║  Then verify your IP: ip a                ║"
echo "║                                           ║"
echo "║  To attack:                               ║"
echo "║  sudo python3 attack.py 192.168.X.X       ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
