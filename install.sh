#!/usr/bin/env python3

import subprocess
import time
import psutil
from datetime import datetime

LOG_FILE = "/var/log/edr_agent.log"

# portas consideradas sensíveis
BLOCKED_PORTS = [23, 21, 80]
ALLOWED_PORTS = [22]

# -------------------------
# FUNÇÃO DE LOG
# -------------------------

def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# -------------------------
# CONFIGURAÇÃO FIREWALL
# -------------------------

def configure_firewall():

    log("Configurando firewall...")

    subprocess.run(["ufw", "--force", "enable"])

    for port in BLOCKED_PORTS:
        subprocess.run(["ufw", "deny", str(port)])
        log(f"Porta bloqueada: {port}")

    for port in ALLOWED_PORTS:
        subprocess.run(["ufw", "allow", str(port)])
        log(f"Porta permitida: {port}")

# -------------------------
# POLÍTICAS SSH
# -------------------------

def configure_ssh():

    ssh_config = "/etc/ssh/sshd_config"

    log("Aplicando políticas SSH")

    with open(ssh_config, "a") as f:
        f.write("\nMaxAuthTries 3\n")
        f.write("PermitRootLogin no\n")

    subprocess.run(["systemctl", "restart", "ssh"])

# -------------------------
# MONITORAMENTO DE PORTAS
# -------------------------

def monitor_ports():

    connections = psutil.net_connections()

    for conn in connections:

        if conn.status == "LISTEN":

            port = conn.laddr.port

            if port in BLOCKED_PORTS:
                log(f"ALERTA: Porta sensível aberta -> {port}")

# -------------------------
# DETECÇÃO DE CONEXÕES SUSPEITAS
# -------------------------

def detect_network_anomaly():

    connections = psutil.net_connections(kind="inet")

    ip_count = {}

    for conn in connections:

        if conn.raddr:

            ip = conn.raddr.ip
            ip_count[ip] = ip_count.get(ip, 0) + 1

    for ip, count in ip_count.items():

        if count > 40:
            log(f"Possível scan ou ataque detectado de {ip} ({count} conexões)")

# -------------------------
# DETECÇÃO DE PROCESSOS SUSPEITOS
# -------------------------

def monitor_processes():

    suspicious_processes = ["nmap", "hydra", "netcat", "nc"]

    for proc in psutil.process_iter(['name']):

        try:

            if proc.info['name'] in suspicious_processes:
                log(f"Processo suspeito detectado: {proc.info['name']}")

        except:
            pass

# -------------------------
# LOOP PRINCIPAL
# -------------------------

def edr_loop():

    log("EDR iniciado")

    while True:

        monitor_ports()
        detect_network_anomaly()
        monitor_processes()

        time.sleep(300)

# -------------------------
# MAIN
# -------------------------

if __name__ == "__main__":

    configure_firewall()
    configure_ssh()

    edr_loop()
