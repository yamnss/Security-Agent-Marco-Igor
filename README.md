# 🛡️ Linux EDR Agent + Dashboard

Sistema de detecção e resposta (EDR) desenvolvido em Python para ambientes Linux (Ubuntu), com foco em:

* Detecção de brute force SSH
* Detecção de port scan
* Bloqueio automático via UFW
* Classificação de risco (LOW / MEDIUM / HIGH)
* Dashboard web em tempo real (Flask)
* Armazenamento de eventos em SQLite

---

# 🚀 Instalação (máquina nova)

## ⚠️ 1. Corrigir repositórios (Ubuntu EOL)

Se o sistema estiver com erro de `apt update` (ex: versão *oracular*), execute:

```bash
sudo rm -f /etc/apt/sources.list.d/ubuntu.sources

sudo tee /etc/apt/sources.list > /dev/null <<EOF
deb http://old-releases.ubuntu.com/ubuntu/ $(lsb_release -cs) main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $(lsb_release -cs)-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $(lsb_release -cs)-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $(lsb_release -cs)-security main restricted universe multiverse
EOF
```

---

## 📦 2. Atualizar sistema

```bash
sudo apt update
sudo apt upgrade -y
```

---

## 🧰 3. Instalar dependências

```bash
sudo apt install -y \
  python3 python3-venv python3-pip \
  ufw conntrack net-tools \
  openssh-server sqlite3 curl
```

---

## 📁 4. Criar estrutura

```bash
sudo mkdir -p /opt/edr-agent/dashboard
```

---

## 📥 5. Baixar projeto

```bash
cd /opt/edr-agent

sudo curl -O https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPO/main/edr_agent.py
sudo chmod +x edr_agent.py
```

---

## 🧪 6. Criar banco de dados

```bash
sqlite3 /opt/edr-agent/edr.db <<EOF
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    level TEXT,
    event_type TEXT,
    ip TEXT,
    message TEXT
);
EOF
```

---

## ⚙️ 7. Criar config.json

```bash
sudo nano /opt/edr-agent/config.json
```

```json
{
  "blocked_ports": [23, 21, 80],
  "allowed_ports": [22],
  "check_interval": 5,
  "ssh_medium_threshold": 3,
  "ssh_high_threshold": 6,
  "ssh_fail_window": 300,
  "scan_threshold": 5,
  "scan_window": 30,
  "event_cooldown": 30,
  "whitelist_ips": ["SEU_IP"],
  "enable_geolocation": false,
  "allowed_countries": ["BR"]
}
```

---

## 🧱 8. Criar serviço do agente

```bash
sudo nano /etc/systemd/system/edr-agent.service
```

```ini
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/edr-agent/edr_agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

## 🌐 9. Instalar dashboard

```bash
cd /opt/edr-agent/dashboard

sudo python3 -m venv venv
sudo venv/bin/pip install flask
```

---

## 📊 10. Criar serviço do dashboard

```bash
sudo nano /etc/systemd/system/edr-dashboard.service
```

```ini
[Unit]
Description=Linux EDR Dashboard
After=network.target edr-agent.service

[Service]
ExecStart=/opt/edr-agent/dashboard/venv/bin/python /opt/edr-agent/dashboard/dashboard.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

## ▶️ 11. Ativar serviços

```bash
sudo systemctl daemon-reload
sudo systemctl enable edr-agent edr-dashboard
sudo systemctl start edr-agent edr-dashboard
```

---

## 🔥 12. Liberar porta do dashboard

```bash
sudo ufw allow 5000/tcp
```

---

# 🌐 Acesso ao Dashboard

```text
http://IP_DA_VM:5000
```

---

# 🧪 Testes

## 🔍 Port scan (Kali)

```bash
nmap -Pn -p 1-100 IP
```

## 🔐 SSH brute force

```bash
ssh usuario@IP
# errar senha várias vezes
```

Resultado esperado:

* 3 tentativas → MEDIUM
* 6 tentativas → HIGH + bloqueio

---

# 📊 Funcionalidades

* ✔ Monitoramento de portas
* ✔ Detecção de scan
* ✔ Detecção de brute force
* ✔ Bloqueio automático de IP
* ✔ Classificação de risco
* ✔ Dashboard em tempo real
* ✔ Estatísticas e Top IPs

---

# ⚠️ Observações

* Bloqueio é permanente (UFW)
* Geolocalização opcional
* Pode exigir rede em modo **Bridge** para testes externos

---

# 📌 Autor

Projeto desenvolvido para fins acadêmicos (TCC) com foco em segurança ofensiva e defensiva em ambientes Linux.
