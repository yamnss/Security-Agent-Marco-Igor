#!/usr/bin/env bash

set -e

INSTALL_DIR="/opt/edr-agent"
SERVICE_AGENT="/etc/systemd/system/edr-agent.service"
SERVICE_DASH="/etc/systemd/system/edr-dashboard.service"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; }

# -------------------------
# ROOT CHECK
# -------------------------
if [ "$EUID" -ne 0 ]; then
  error "Execute como root: sudo bash uninstall.sh"
  exit 1
fi

info "Iniciando remoção do EDR..."

# -------------------------
# PARAR SERVIÇOS
# -------------------------
info "Parando serviços..."

systemctl stop edr-agent 2>/dev/null || true
systemctl stop edr-dashboard 2>/dev/null || true

systemctl disable edr-agent 2>/dev/null || true
systemctl disable edr-dashboard 2>/dev/null || true

# -------------------------
# REMOVER SERVICES
# -------------------------
info "Removendo services..."

rm -f "$SERVICE_AGENT"
rm -f "$SERVICE_DASH"

systemctl daemon-reload

# -------------------------
# REMOVER ARQUIVOS
# -------------------------
info "Removendo arquivos..."

rm -rf "$INSTALL_DIR"

# -------------------------
# PERGUNTAR SOBRE FIREWALL
# -------------------------
echo ""
read -p "Deseja remover TODAS as regras do UFW? (y/n): " ufw_choice

if [[ "$ufw_choice" == "y" || "$ufw_choice" == "Y" ]]; then
  warn "Resetando firewall..."

  ufw --force reset
  ufw disable

  info "Firewall limpo"
else
  info "Regras do firewall mantidas"
fi

# -------------------------
# FINAL
# -------------------------
echo ""
info "EDR removido com sucesso 🚀"
