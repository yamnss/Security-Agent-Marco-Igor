#!/usr/bin/env bash
set -u

REPO_USER="yamnss"
REPO_NAME="Security-Agent-Marco-Igor"
AGENT_URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/main/edr.agent.py"

INSTALL_DIR="/opt/edr-agent"
AGENT_FILE="${INSTALL_DIR}/edr_agent.py"
LOG_FILE="/var/log/edr_agent.log"
SERVICE_FILE="/etc/systemd/system/edr-agent.service"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; }
die() { error "$1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
  die "Execute como root: sudo bash install.sh"
fi

info "Verificando travas do apt..."
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
   || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
   || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
  warn "Aguardando apt..."
  sleep 5
done

CODENAME=$(lsb_release -cs 2>/dev/null || echo "unknown")
info "Codename detectado: $CODENAME"

case "$CODENAME" in
  oracular|mantic|lunar|kinetic|impish|hirsute|groovy)
    warn "Versão EOL detectada, corrigindo repositórios..."

    rm -f /etc/apt/sources.list.d/ubuntu.sources

    cat > /etc/apt/sources.list <<EOF
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe multiverse
EOF
    ;;
esac

info "Atualizando APT..."
apt-get update -y || die "Erro no apt update"

info "Instalando dependências..."
apt-get install -y \
  curl \
  ufw \
  conntrack \
  openssh-server \
  python3 \
  python3-psutil \
  net-tools || die "Erro ao instalar pacotes"

command -v python3 >/dev/null || die "python3 não encontrado"
command -v ufw >/dev/null || die "ufw não encontrado"
command -v conntrack >/dev/null || die "conntrack não encontrado"
command -v curl >/dev/null || die "curl não encontrado"

info "Criando estrutura..."
mkdir -p "$INSTALL_DIR" || die "Falha ao criar $INSTALL_DIR"

touch "$LOG_FILE" || die "Falha ao criar $LOG_FILE"
chown root:root "$LOG_FILE"
chmod 644 "$LOG_FILE"

info "Baixando agente..."
curl -fsSL "$AGENT_URL" -o "$AGENT_FILE" || die "Erro ao baixar agente"

if [ ! -s "$AGENT_FILE" ]; then
  die "Arquivo do agente veio vazio"
fi

if grep -q "404: Not Found" "$AGENT_FILE"; then
  die "Arquivo inválido (404)"
fi

chmod +x "$AGENT_FILE"

info "Validando código..."
python3 -m py_compile "$AGENT_FILE" || die "Erro de sintaxe no agente"

info "Criando serviço..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 $AGENT_FILE
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

systemctl enable ssh >/dev/null 2>&1
systemctl start ssh >/dev/null 2>&1

ufw --force enable >/dev/null 2>&1

systemctl enable edr-agent || die "Erro ao habilitar serviço"
systemctl restart edr-agent || die "Erro ao iniciar serviço"

info "Instalação concluída 🚀"
echo ""
echo "Log:"
echo "tail -f $LOG_FILE"
echo ""
systemctl status edr-agent --no-pager
