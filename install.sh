#!/bin/bash

echo "Instalando Linux EDR Agent..."

# atualizar sistema
sudo apt update

# instalar dependências
sudo apt install -y python3 python3-psutil ufw curl

# instalar SSH se não existir
if ! command -v sshd &> /dev/null
then
    echo "Instalando OpenSSH Server..."
    sudo apt install -y openssh-server
fi

# criar diretório do agente
sudo mkdir -p /opt/edr-agent

# baixar agente
sudo curl -o /opt/edr-agent/edr_agent.py \
https://raw.githubusercontent.com/yamnss/Security-Agent-Marco-Igor/main/edr.agent.py

# permissões
sudo chmod +x /opt/edr-agent/edr_agent.py

# criar arquivo de serviço
sudo tee /etc/systemd/system/edr-agent.service > /dev/null <<EOF
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

# recarregar systemd
sudo systemctl daemon-reload

# habilitar serviço
sudo systemctl enable edr-agent

# iniciar agente
sudo systemctl start edr-agent

echo "EDR instalado com sucesso!"
