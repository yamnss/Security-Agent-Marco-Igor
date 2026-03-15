#!/bin/bash

echo "================================="
echo " Instalando Linux EDR Agent"
echo "================================="

# atualizar pacotes

sudo apt update -y

# instalar dependências

sudo apt install python3 python3-pip ufw curl -y

# instalar biblioteca python

pip3 install psutil

# criar diretório do agente

sudo mkdir -p /opt/edr-agent

# baixar agente do github

sudo curl -o /opt/edr-agent/edr_agent.py https://raw.githubusercontent.com/yamnss/Security-Agent-Marco-Igor/refs/heads/main/edr.agent.py?token=GHSAT0AAAAAADX4KNECJ5OTH2T7VM6VMTIK2NXCJPA

# dar permissão de execução

sudo chmod +x /opt/edr-agent/edr_agent.py

# criar arquivo de log

sudo touch /var/log/edr_agent.log
sudo chmod 666 /var/log/edr_agent.log

# criar serviço systemd

sudo bash -c 'cat << EOF > /etc/systemd/system/edr-agent.service
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/edr-agent/edr_agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF'

# ativar serviço

sudo systemctl daemon-reload
sudo systemctl enable edr-agent
sudo systemctl start edr-agent

echo "================================="
echo "Instalação concluída!"
echo "EDR ativo no sistema."
echo "================================="
