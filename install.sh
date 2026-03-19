#!/usr/bin/env bash
set -u

REPO_USER="yamnss"
REPO_NAME="Security-Agent-Marco-Igor"
AGENT_RAW_URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/main/edr_agent.py"

INSTALL_DIR="/opt/edr-agent"
AGENT_FILE="${INSTALL_DIR}/edr_agent.py"
LOG_FILE="/var/log/edr_agent.log"
SERVICE_FILE="/etc/systemd/system/edr-agent.service"
SSH_CONFIG="/etc/ssh/sshd_config"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERRO]${NC} $1"; }
die()     { error "$1"; exit 1; }

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    die "Execute este script como root: sudo bash install.sh"
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
      die "apt/dpkg permaneceu bloqueado por mais de 3 minutos."
    fi
  done
}

check_sources_list() {
  info "Validando repositórios do APT..."

  if grep -Rqi "old-releases.ubuntu.com" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    die "Foram encontradas entradas com old-releases.ubuntu.com. Corrija os repositórios antes de continuar."
  fi

  if ! grep -RqiE "archive.ubuntu.com|security.ubuntu.com|br.archive.ubuntu.com" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    warn "Não encontrei repositórios padrão do Ubuntu. Vou continuar, mas o apt pode falhar."
  fi
}

apt_update_safe() {
  wait_for_apt
  info "Atualizando índices do APT..."
  if ! apt-get update -y; then
    die "Falha no apt-get update. Verifique /etc/apt/sources.list e conectividade."
  fi
}

install_packages() {
  wait_for_apt
  info "Instalando dependências..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    ufw \
    conntrack \
    openssh-server \
    python3 \
    python3-psutil \
    ca-certificates \
    net-tools || die "Falha ao instalar dependências."
}

validate_commands() {
  info "Validando binários instalados..."
  command -v python3 >/dev/null 2>&1 || die "python3 não encontrado."
  command -v curl >/dev/null 2>&1 || die "curl não encontrado."
  command -v ufw >/dev/null 2>&1 || die "ufw não encontrado."
  command -v conntrack >/dev/null 2>&1 || die "conntrack não encontrado."
  command -v sshd >/dev/null 2>&1 || warn "sshd não encontrado no PATH, mas o pacote pode estar instalado."
}

prepare_dirs_and_files() {
  info "Criando diretórios e arquivos..."
  mkdir -p "$INSTALL_DIR" || die "Falha ao criar $INSTALL_DIR"

  touch "$LOG_FILE" || die "Falha ao criar $LOG_FILE"
  chown root:root "$LOG_FILE" || die "Falha ao ajustar dono de $LOG_FILE"
  chmod 644 "$LOG_FILE" || die "Falha ao ajustar permissões de $LOG_FILE"

  if [ -f "$SSH_CONFIG" ]; then
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)" || die "Falha ao criar backup do sshd_config"
  else
    warn "$SSH_CONFIG não encontrado. O hardening de SSH pode ser ignorado pelo agente."
  fi
}

download_agent() {
  info "Baixando agente..."
  curl -fsSL "$AGENT_RAW_URL" -o "$AGENT_FILE" || die "Falha ao baixar edr_agent.py do GitHub."

  if [ ! -s "$AGENT_FILE" ]; then
    die "O arquivo baixado está vazio."
  fi

  if grep -q "404: Not Found" "$AGENT_FILE"; then
    die "O arquivo baixado contém 404. Verifique REPO_USER, REPO_NAME e o nome do arquivo."
  fi

  chmod 755 "$AGENT_FILE" || die "Falha ao ajustar permissões de $AGENT_FILE"
}

validate_python_syntax() {
  info "Validando sintaxe do agente..."
  python3 -m py_compile "$AGENT_FILE" || die "O edr_agent.py tem erro de sintaxe."
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

  chmod 644 "$SERVICE_FILE" || die "Falha ao ajustar permissões do service."
}

enable_services() {
  info "Habilitando SSH..."
  systemctl enable ssh >/dev/null 2>&1 || warn "Não consegui habilitar ssh."
  systemctl start ssh >/dev/null 2>&1 || warn "Não consegui iniciar ssh."

  info "Configurando firewall..."
  ufw --force enable >/dev/null 2>&1 || die "Falha ao habilitar o UFW."

  info "Recarregando systemd..."
  systemctl daemon-reload || die "Falha no daemon-reload."

  info "Habilitando e iniciando o EDR..."
  systemctl enable edr-agent || die "Falha ao habilitar edr-agent."
  systemctl restart edr-agent || die "Falha ao iniciar edr-agent."
}

post_checks() {
  info "Executando validações finais..."

  systemctl is-enabled edr-agent >/dev/null 2>&1 || die "edr-agent não ficou habilitado."
  systemctl is-active edr-agent >/dev/null 2>&1 || die "edr-agent não ficou ativo."

  [ -f "$SERVICE_FILE" ] || die "Arquivo do serviço não existe."
  [ -f "$AGENT_FILE" ] || die "Arquivo do agente não existe."
  [ -f "$LOG_FILE" ] || die "Arquivo de log não existe."

  info "Status do serviço:"
  systemctl --no-pager --full status edr-agent || true

  info "Últimas linhas do log:"
  tail -n 10 "$LOG_FILE" || true
}

main() {
  require_root
  check_sources_list
  apt_update_safe
  install_packages
  validate_commands
  prepare_dirs_and_files
  download_agent
  validate_python_syntax
  create_service
  enable_services
  post_checks

  echo
  info "Instalação concluída com sucesso."
  echo "Agente:   $AGENT_FILE"
  echo "Serviço:  $SERVICE_FILE"
  echo "Log:      $LOG_FILE"
  echo
  echo "Acompanhar log em tempo real:"
  echo "tail -f $LOG_FILE"
}

main "$@"
