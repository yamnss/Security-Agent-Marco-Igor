#!/usr/bin/env bash
set -u

REPO_USER="yamnss"
REPO_NAME="Security-Agent-Marco-Igor"
AGENT_URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/main/edr_agent.py"

INSTALL_DIR="/opt/edr-agent"
AGENT_FILE="${INSTALL_DIR}/edr_agent.py"
LOG_FILE="/var/log/edr_agent.log"
SERVICE_FILE="/etc/systemd/system/edr-agent.service"
SSH_CONFIG="/etc/ssh/sshd_config"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; }
die() { error "$1"; exit 1; }

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    die "Execute como root: sudo bash install.sh"
  fi
}

wait_for_apt() {
  info "Verificando travas do apt/dpkg..."
  local waited=0

  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    warn "Aguardando liberação do apt/dpkg..."
    sleep 5
    waited=$((waited + 5))

    if [ "$waited" -ge 180 ]; then
      die "apt/dpkg ficou bloqueado por mais de 3 minutos."
    fi
  done
}

get_codename() {
  if command -v lsb_release >/dev/null 2>&1; then
    lsb_release -cs
    return
  fi

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${VERSION_CODENAME:-unknown}"
    return
  fi

  echo "unknown"
}

fix_eol_sources_if_needed() {
  local codename
  codename="$(get_codename)"

  info "Codename detectado: ${codename}"

  case "$codename" in
    oracular|mantic|lunar|kinetic|impish|hirsute|groovy|eoan|disco|cosmic|artful|zesty|yakkety|xenial)
      warn "Versão potencialmente fora de suporte detectada (${codename}). Ajustando repositórios para old-releases..."

      cat > /etc/apt/sources.list <<EOF
deb http://old-releases.ubuntu.com/ubuntu/ ${codename} main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ ${codename}-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ ${codename}-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ ${codename}-security main restricted universe multiverse
EOF
      ;;
    *)
      info "Nenhum ajuste automático de repositório foi necessário."
      ;;
  esac
}

apt_update_safe() {
  wait_for_apt
  info "Atualizando índices do APT..."
  apt-get update -y || die "Falha no apt-get update. Verifique os repositórios."
}

install_base_packages() {
  wait_for_apt
  info "Instalando dependências..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    curl \
    ufw \
    conntrack \
    net-tools \
    openssh-server \
    python3 \
    python3-psutil || die "Falha ao instalar dependências."
}

validate_commands() {
  info "Validando binários..."
  command -v python3 >/dev/null 2>&1 || die "python3 não encontrado."
  command -v curl >/dev/null 2>&1 || die "curl não encontrado."
  command -v ufw >/dev/null 2>&1 || die "ufw não encontrado."
  command -v conntrack >/dev/null 2>&1 || die "conntrack não encontrado."
}

prepare_filesystem() {
  info "Preparando diretórios e arquivos..."
  mkdir -p "$INSTALL_DIR" || die "Falha ao criar ${INSTALL_DIR}"

  touch "$LOG_FILE" || die "Falha ao criar ${LOG_FILE}"
  chown root:root "$LOG_FILE" || die "Falha ao ajustar dono do log"
  chmod 644 "$LOG_FILE" || die "Falha ao ajustar permissões do log"

  if [ -f "$SSH_CONFIG" ]; then
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)" || warn "Não consegui criar backup do sshd_config"
  else
    warn "Arquivo ${SSH_CONFIG} não encontrado. O agente pode ignorar hardening SSH."
  fi
}

download_agent() {
  info "Baixando edr_agent.py..."
  curl -fsSL "$AGENT_URL" -o "$AGENT_FILE" || die "Falha ao baixar edr_agent.py"

  if [ ! -s "$AGENT_FILE" ]; then
    die "O arquivo do agente foi baixado vazio."
  fi

  if grep -q "404: Not Found" "$AGENT_FILE"; then
    die "O download retornou 404. Verifique REPO_USER, REPO_NAME e o nome do arquivo no GitHub."
  fi

  chmod 755 "$AGENT_FILE" || die "Falha ao ajustar permissão do agente"
}

validate_agent() {
  info "Validando sintaxe do agente..."
  python3 -m py_compile "$AGENT_FILE" || die "O edr_agent.py contém erro de sintaxe."
}

create_service() {
  info "Criando serviço systemd..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 ${AGENT_FILE}
Restart=always
RestartSec=5
User=root
WorkingDirectory=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$SERVICE_FILE" || die "Falha ao ajustar permissões do service"
}

enable_everything() {
  info "Habilitando SSH..."
  systemctl enable ssh >/dev/null 2>&1 || warn "Não foi possível habilitar ssh"
  systemctl start ssh >/dev/null 2>&1 || warn "Não foi possível iniciar ssh"

  info "Habilitando firewall..."
  ufw --force enable >/dev/null 2>&1 || die "Falha ao habilitar UFW"

  info "Recarregando systemd..."
  systemctl daemon-reload || die "Falha ao executar daemon-reload"

  info "Habilitando e iniciando o EDR..."
  systemctl enable edr-agent || die "Falha ao habilitar edr-agent"
  systemctl restart edr-agent || die "Falha ao iniciar edr-agent"
}

post_checks() {
  info "Executando validações finais..."

  systemctl is-enabled edr-agent >/dev/null 2>&1 || die "edr-agent não ficou habilitado"
  systemctl is-active edr-agent >/dev/null 2>&1 || die "edr-agent não ficou ativo"

  [ -f "$AGENT_FILE" ] || die "Arquivo do agente não encontrado"
  [ -f "$SERVICE_FILE" ] || die "Arquivo do serviço não encontrado"
  [ -f "$LOG_FILE" ] || die "Arquivo de log não encontrado"

  info "Status do serviço:"
  systemctl --no-pager --full status edr-agent || true

  info "Últimas linhas do log:"
  tail -n 10 "$LOG_FILE" || true
}

main() {
  require_root
  fix_eol_sources_if_needed
  apt_update_safe
  install_base_packages
  validate_commands
  prepare_filesystem
  download_agent
  validate_agent
  create_service
  enable_everything
  post_checks

  echo
  info "Instalação concluída."
  echo "Agente:  $AGENT_FILE"
  echo "Serviço: $SERVICE_FILE"
  echo "Log:     $LOG_FILE"
  echo
  echo "Para acompanhar o log em tempo real:"
  echo "tail -f $LOG_FILE"
}

main "$@"
