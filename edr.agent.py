#!/usr/bin/env python3

import subprocess
import time
import psutil
from datetime import datetime

LOG_FILE = "/var/log/edr_agent.log"

BLOCKED_PORTS = [23, 21, 80]
ALLOWED_PORTS = [22]

blocked_ips = set()
seen_connections = set()
last_position = 0
ufw_last_position = 0

# -------------------------
# LOG
# -------------------------
def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# -------------------------
# FIREWALL
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

    subprocess.run(["ufw", "logging", "on"])

# -------------------------
# SSH HARDENING
# -------------------------
def configure_ssh():
    ssh_config = "/etc/ssh/sshd_config"

    log("Aplicando políticas SSH")

    with open(ssh_config, "a") as f:
        f.write("\nMaxAuthTries 6\n")
        f.write("PermitRootLogin no\n")

    subprocess.run(["systemctl", "restart", "ssh"])

# -------------------------
# MONITORAMENTO DE PORTAS
# -------------------------
def monitor_ports():
    global seen_connections

    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if conn.raddr and conn.status in ["ESTABLISHED", "SYN_RECV"]:
                local_port = conn.laddr.port
                remote_ip = conn.raddr.ip

                conn_id = f"{remote_ip}:{local_port}"

                if conn_id in seen_connections:
                    continue

                seen_connections.add(conn_id)

                if local_port in BLOCKED_PORTS:
                    log(f"[CRITICAL] Acesso proibido: {remote_ip} -> porta {local_port}")

                    subprocess.run([
                        "ufw", "insert", "1", "deny",
                        "from", remote_ip, "to", "any", "port", str(local_port)
                    ])

                    subprocess.run(["conntrack", "-D", "-s", remote_ip])

                    log(f"[ACTION] IP bloqueado: {remote_ip}")

                elif local_port == 22:
                    log(f"[INFO] Conexão SSH de {remote_ip}")

    except Exception as e:
        log(f"[ERRO] monitor_ports: {e}")

# -------------------------
# DETECÇÃO DE SCAN
# -------------------------
def detect_network_anomaly():
    global ufw_last_position

    try:
        log_file = "/var/log/ufw.log"
        ip_count = {}

        with open(log_file, "r") as f:
            f.seek(ufw_last_position)
            lines = f.readlines()
            ufw_last_position = f.tell()

        for line in lines:
            if "BLOCK" in line and "SRC=" in line:
                parts = line.split()

                for part in parts:
                    if part.startswith("SRC="):
                        ip = part.split("=")[1]
                        ip_count[ip] = ip_count.get(ip, 0) + 1

        for ip, count in ip_count.items():
            if count > 5:
                log(f"[WARNING] SCAN detectado: {ip} ({count} tentativas)")

    except Exception as e:
        log(f"[ERRO] network anomaly: {e}")

# -------------------------
# DETECÇÃO SSH BRUTE FORCE
# -------------------------
def detect_ssh_bruteforce():
    global blocked_ips
    global last_position

    try:
        log_file = "/var/log/auth.log"
        ip_count = {}

        with open(log_file, "r") as f:
            f.seek(last_position)
            lines = f.readlines()
            last_position = f.tell()

        for line in lines:
            if "Failed password for" in line and "ssh2" in line:

                parts = line.split()

                for i in range(len(parts)):
                    if parts[i] == "from":
                        ip = parts[i + 1]
                        ip_count[ip] = ip_count.get(ip, 0) + 1

        for ip, count in ip_count.items():
            if count >= 3 and ip not in blocked_ips:

                blocked_ips.add(ip)

                log(f"[CRITICAL] BRUTE FORCE SSH: {ip} ({count} tentativas)")

                subprocess.run([
                    "ufw", "insert", "1", "deny",
                    "from", ip, "to", "any", "port", "22"
                ])

                subprocess.run(["conntrack", "-D", "-s", ip])

                log(f"[ACTION] IP bloqueado (SSH): {ip}")

    except Exception as e:
        log(f"[ERRO] SSH brute force: {e}")

# -------------------------
# LOOP PRINCIPAL
# -------------------------
def edr_loop():
    log("EDR iniciado")

    while True:
        monitor_ports()
        detect_network_anomaly()
        detect_ssh_bruteforce()

        if len(seen_connections) > 1000:
            seen_connections.clear()

        time.sleep(5)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    configure_firewall()
    configure_ssh()
    edr_loop()
