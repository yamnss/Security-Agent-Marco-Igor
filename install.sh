#!/usr/bin/env bash

set -e

REPO_USER="yamnss"
REPO_NAME="Security-Agent-Marco-Igor"

AGENT_URL="https://raw.githubusercontent.com/$REPO_USER/$REPO_NAME/main/edr.agent.py"
DASHBOARD_URL="https://raw.githubusercontent.com/$REPO_USER/$REPO_NAME/main/dashboard.py"

INSTALL_DIR="/opt/edr-agent"
DASHBOARD_DIR="$INSTALL_DIR/dashboard"

LOG_FILE="/var/log/edr_agent.log"
UFW_LOG="/var/log/ufw.log"
DB_FILE="$INSTALL_DIR/edr.db"
CONFIG_FILE="$INSTALL_DIR/config.json"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; exit 1; }

# -------------------------
# ROOT CHECK
# -------------------------
[ "$EUID" -ne 0 ] && error "Execute como root: sudo bash install.sh"

# -------------------------
# APT LOCK
# -------------------------
wait_for_apt() {
  info "Verificando travas do apt/dpkg..."

  local waited=0
  local max_wait=600

  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    warn "Aguardando apt/dpkg liberar..."
    sleep 5
    waited=$((waited + 5))

    if [ "$waited" -ge "$max_wait" ]; then
      error "apt/dpkg ficou travado por mais de $max_wait segundos. Verifique unattended-upgrades."
    fi
  done
}

wait_for_apt

# -------------------------
# CORRIGIR REPOSITÓRIOS EOL
# -------------------------
CODENAME=$(lsb_release -cs 2>/dev/null || echo "unknown")
info "Codename detectado: $CODENAME"

case "$CODENAME" in
  oracular|mantic|lunar|kinetic|impish|hirsute|groovy)
    warn "Versão EOL detectada. Corrigindo repositórios para old-releases..."

    rm -f /etc/apt/sources.list.d/ubuntu.sources

    cat > /etc/apt/sources.list <<EOF
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe multiverse
EOF
    ;;
esac

# -------------------------
# APT UPDATE
# -------------------------
wait_for_apt
info "Atualizando sistema..."
apt-get update -y || error "Falha no apt update"

# -------------------------
# DEPENDÊNCIAS
# -------------------------
wait_for_apt
info "Instalando dependências..."

DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 \
  python3-venv \
  python3-pip \
  python3-psutil \
  ufw \
  rsyslog \
  conntrack \
  net-tools \
  openssh-server \
  sqlite3 \
  curl || error "Falha ao instalar pacotes"

# -------------------------
# ESTRUTURA
# -------------------------
info "Criando estrutura..."

mkdir -p "$DASHBOARD_DIR"

touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

touch "$UFW_LOG"
chmod 644 "$UFW_LOG"

systemctl enable --now rsyslog >/dev/null 2>&1 || true

# -------------------------
# DOWNLOAD
# -------------------------
info "Baixando agente..."

curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/edr_agent.py" || error "Erro ao baixar agente"
chmod +x "$INSTALL_DIR/edr_agent.py"

info "Baixando dashboard..."

curl -fsSL "$DASHBOARD_URL" -o "$DASHBOARD_DIR/dashboard.py" || error "Erro ao baixar dashboard"

# -------------------------
# DATABASE
# -------------------------
info "Criando banco..."

sqlite3 "$DB_FILE" <<EOF
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    level TEXT,
    event_type TEXT,
    ip TEXT,
    message TEXT
);
EOF

# -------------------------
# CONFIG
# -------------------------
info "Criando config..."

cat > "$CONFIG_FILE" <<EOF
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
  "whitelist_ips": ["$(hostname -I | awk '{print $1}')"],
  "enable_geolocation": false,
  "allowed_countries": ["BR"]
}
EOF

# -------------------------
# VALIDAR PYTHON
# -------------------------
info "Validando agente..."

python3 -m py_compile "$INSTALL_DIR/edr_agent.py" || error "Erro de sintaxe no agente"

# -------------------------
# VENV DASHBOARD
# -------------------------
info "Configurando dashboard..."

python3 -m venv "$DASHBOARD_DIR/venv"
"$DASHBOARD_DIR/venv/bin/pip" install flask

# -------------------------
# SERVICE AGENTE
# -------------------------
info "Criando serviço do agente..."

cat > /etc/systemd/system/edr-agent.service <<EOF
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 $INSTALL_DIR/edr_agent.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# -------------------------
# SERVICE DASHBOARD
# -------------------------
info "Criando serviço do dashboard..."

cat > /etc/systemd/system/edr-dashboard.service <<EOF
[Unit]
Description=Linux EDR Dashboard
After=network.target edr-agent.service
Wants=edr-agent.service

[Service]
ExecStart=$DASHBOARD_DIR/venv/bin/python $DASHBOARD_DIR/dashboard.py
Restart=always
RestartSec=5
User=root
WorkingDirectory=$DASHBOARD_DIR

[Install]
WantedBy=multi-user.target
EOF

# -------------------------
# FIREWALL BASE
# -------------------------
info "Configurando firewall base..."

ufw --force enable
ufw logging on
ufw allow 5000/tcp

# -------------------------
# ATIVAR SERVIÇOS
# -------------------------
info "Ativando serviços..."

systemctl daemon-reload
systemctl enable edr-agent edr-dashboard
systemctl restart edr-agent edr-dashboard

# -------------------------
# FINAL
# -------------------------
info "Instalação concluída 🚀"

echo ""
echo "Dashboard:"
echo "http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "Logs:"
echo "tail -f $LOG_FILE"
echo ""
echo "Firewall:"
echo "sudo ufw status numbered"
