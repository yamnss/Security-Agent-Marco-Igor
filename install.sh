#!/bin/bash

set -e

echo "[+] Instalando EDR Agent..."

# =========================
# DEPENDÊNCIAS
# =========================
sudo apt update -y
sudo apt install -y ufw conntrack net-tools openssh-server python3

# =========================
# ESTRUTURA
# =========================
sudo mkdir -p /opt/edr-agent

# =========================
# LOG
# =========================
sudo touch /var/log/edr_agent.log
sudo chmod 666 /var/log/edr_agent.log

# =========================
# BAIXAR AGENT (do próprio repo)
# =========================
echo "[+] Baixando agent..."

sudo curl -o /opt/edr-agent/edr_agent.py https://raw.githubusercontent.com/yamnss/Security-Agent-Marco-Igor/main/edr_agent.py

sudo chmod +x /opt/edr-agent/edr_agent.py

# =========================
# SERVICE
# =========================
echo "[+] Criando serviço..."

sudo tee /etc/systemd/system/edr-agent.service > /dev/null << EOF
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/edr-agent/edr_agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# =========================
# START
# =========================
sudo systemctl daemon-reload
sudo systemctl enable edr-agent
sudo systemctl restart edr-agent

# =========================
# FIREWALL
# =========================
sudo ufw --force enable

echo "[✔] EDR instalado com sucesso!"
sudo systemctl status edr-agent --no-pager
