#!/usr/bin/env python3

import os
import re
import json
import time
import psutil
import urllib.request
import subprocess
from datetime import datetime

LOG_FILE = "/var/log/edr_agent.log"
STATS_FILE = "/var/log/edr_stats.log"
SSH_CONFIG = "/etc/ssh/sshd_config"
AUTH_LOG = "/var/log/auth.log"
UFW_LOG = "/var/log/ufw.log"

BLOCKED_PORTS = [23, 21, 80]
ALLOWED_PORTS = [22]

CHECK_INTERVAL = 5

SSH_MEDIUM_THRESHOLD = 3
SSH_HIGH_THRESHOLD = 6
SSH_FAIL_WINDOW = 300

SCAN_THRESHOLD = 5
SCAN_WINDOW = 30

EVENT_COOLDOWN = 30

# ALTERE AQUI
WHITELIST_IPS = [
    "192.168.18.1",
]

# ALTERE AQUI
ENABLE_GEOLOCATION = True
ALLOWED_COUNTRIES = ["BR"]

last_auth_position = 0
last_ufw_position = 0

last_event_log = {}
ssh_failures = {}
scan_attempts = {}
blocked_ips = set()

stats = {
    "LOW": 0,
    "MEDIUM": 0,
    "HIGH": 0,
    "BLOCKED": 0,
    "SSH_FAILURES": 0,
    "SCANS": 0,
    "SSH_CONNECTIONS": 0,
}


def log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
        f.flush()


def save_stats():
    data = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats
    }

    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def log_event(level, message):
    if level in stats:
        stats[level] += 1

    log(f"[{level}] {message}")
    save_stats()


def log_with_cooldown(event_key, level, message, cooldown=EVENT_COOLDOWN):
    now = time.time()
    last = last_event_log.get(event_key, 0)

    if now - last >= cooldown:
        log_event(level, message)
        last_event_log[event_key] = now


def safe_run(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        log_event("LOW", f"Falha ao executar comando {' '.join(cmd)}: {e}")


def safe_run_output(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout or ""
    except Exception as e:
        log_event("LOW", f"Falha ao obter saída do comando {' '.join(cmd)}: {e}")
        return ""


def is_private_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.20.") or
        ip.startswith("172.21.") or
        ip.startswith("172.22.") or
        ip.startswith("172.23.") or
        ip.startswith("172.24.") or
        ip.startswith("172.25.") or
        ip.startswith("172.26.") or
        ip.startswith("172.27.") or
        ip.startswith("172.28.") or
        ip.startswith("172.29.") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.") or
        ip.startswith("127.")
    )


def get_country(ip):
    if is_private_ip(ip):
        return "PRIVATE"

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode())

        if data.get("status") == "success":
            return data.get("countryCode", "UNKNOWN")

    except Exception:
        return "UNKNOWN"

    return "UNKNOWN"


def is_whitelisted(ip):
    return ip in WHITELIST_IPS


def check_geo_policy(ip):
    if not ENABLE_GEOLOCATION:
        return True

    if is_private_ip(ip):
        return True

    country = get_country(ip)

    if country not in ALLOWED_COUNTRIES:
        log_event("HIGH", f"IP fora da região permitida: {ip} país={country}")
        block_ip(ip, "geolocalização não permitida")
        return False

    return True


def ufw_rule_exists(ip, port=None):
    status = safe_run_output(["ufw", "status"])

    if port is None:
        return ip in status

    return ip in status and str(port) in status


def block_ip(ip, reason, port=None):
    if is_whitelisted(ip):
        log_event("LOW", f"IP em whitelist, bloqueio ignorado: {ip}")
        return

    if ip in blocked_ips:
        return

    if ufw_rule_exists(ip, port):
        blocked_ips.add(ip)
        return

    if port is None:
        safe_run(["ufw", "insert", "1", "deny", "from", ip])
    else:
        safe_run(["ufw", "insert", "1", "deny", "from", ip, "to", "any", "port", str(port)])

    safe_run(["conntrack", "-D", "-s", ip])

    blocked_ips.add(ip)
    stats["BLOCKED"] += 1

    log_event("HIGH", f"IP bloqueado: {ip} | motivo={reason}" + (f" | porta={port}" if port else ""))


def configure_firewall():
    log_event("LOW", "Configurando firewall")

    safe_run(["ufw", "--force", "enable"])
    safe_run(["ufw", "logging", "on"])

    for port in BLOCKED_PORTS:
        safe_run(["ufw", "deny", str(port)])
        log_with_cooldown(f"fw-block-{port}", "LOW", f"Porta bloqueada: {port}", cooldown=3600)

    for port in ALLOWED_PORTS:
        safe_run(["ufw", "allow", str(port)])
        log_with_cooldown(f"fw-allow-{port}", "LOW", f"Porta permitida: {port}", cooldown=3600)


def ensure_sshd_option(content, key, value):
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.MULTILINE)

    if pattern.search(content):
        return pattern.sub(f"{key} {value}", content)

    if not content.endswith("\n"):
        content += "\n"

    return content + f"{key} {value}\n"


def configure_ssh():
    if not os.path.exists(SSH_CONFIG):
        log_event("MEDIUM", "sshd_config não encontrado; hardening SSH ignorado")
        return

    try:
        with open(SSH_CONFIG, "r", encoding="utf-8") as f:
            content = f.read()

        updated = ensure_sshd_option(content, "MaxAuthTries", "6")
        updated = ensure_sshd_option(updated, "PermitRootLogin", "no")

        if updated != content:
            with open(SSH_CONFIG, "w", encoding="utf-8") as f:
                f.write(updated)

            log_event("LOW", "Configurações SSH atualizadas")

        safe_run(["systemctl", "restart", "ssh"])

    except Exception as e:
        log_event("MEDIUM", f"Erro ao configurar SSH: {e}")


def monitor_ports():
    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if not conn.raddr:
                continue

            if conn.status not in ("ESTABLISHED", "SYN_RECV"):
                continue

            local_port = conn.laddr.port
            remote_ip = conn.raddr.ip

            if is_whitelisted(remote_ip):
                continue

            check_geo_policy(remote_ip)

            if local_port == 22:
                stats["SSH_CONNECTIONS"] += 1
                log_with_cooldown(
                    f"ssh-conn-{remote_ip}",
                    "LOW",
                    f"Conexão SSH detectada de {remote_ip}",
                    cooldown=15
                )

            if local_port in BLOCKED_PORTS:
                log_event("HIGH", f"Acesso proibido: {remote_ip} -> porta {local_port}")
                block_ip(remote_ip, "acesso a porta sensível", port=local_port)

    except Exception as e:
        log_event("LOW", f"Erro em monitor_ports: {e}")


def detect_network_anomaly():
    global last_ufw_position

    if not os.path.exists(UFW_LOG):
        log_with_cooldown("ufw-log-missing", "MEDIUM", f"Arquivo {UFW_LOG} não encontrado", cooldown=300)
        return

    try:
        with open(UFW_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_ufw_position)
            lines = f.readlines()
            last_ufw_position = f.tell()

        now = time.time()

        for line in lines:
            if "BLOCK" not in line or "SRC=" not in line:
                continue

            match = re.search(r"SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if not match:
                continue

            ip = match.group(1)

            if is_whitelisted(ip):
                continue

            check_geo_policy(ip)

            if ip not in scan_attempts:
                scan_attempts[ip] = []

            scan_attempts[ip].append(now)
            scan_attempts[ip] = [ts for ts in scan_attempts[ip] if now - ts <= SCAN_WINDOW]

            count = len(scan_attempts[ip])

            if count >= SCAN_THRESHOLD:
                stats["SCANS"] += 1
                log_with_cooldown(
                    f"scan-{ip}",
                    "MEDIUM",
                    f"SCAN detectado: {ip} ({count} tentativas em {SCAN_WINDOW}s)",
                    cooldown=SCAN_WINDOW
                )

    except Exception as e:
        log_event("LOW", f"Erro em network anomaly: {e}")


def detect_ssh_bruteforce():
    global last_auth_position

    if not os.path.exists(AUTH_LOG):
        log_with_cooldown("auth-log-missing", "MEDIUM", f"Arquivo {AUTH_LOG} não encontrado", cooldown=300)
        return

    try:
        with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_auth_position)
            lines = f.readlines()
            last_auth_position = f.tell()

        now = time.time()

        for line in lines:
            if "Failed password for" not in line:
                continue

            match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if not match:
                continue

            ip = match.group(1)

            if is_whitelisted(ip):
                log_event("LOW", f"Falha SSH ignorada para IP em whitelist: {ip}")
                continue

            check_geo_policy(ip)

            if ip not in ssh_failures:
                ssh_failures[ip] = []

            ssh_failures[ip].append(now)
            ssh_failures[ip] = [ts for ts in ssh_failures[ip] if now - ts <= SSH_FAIL_WINDOW]

            count = len(ssh_failures[ip])
            stats["SSH_FAILURES"] += 1

            if count >= SSH_HIGH_THRESHOLD:
                log_event("HIGH", f"BRUTE FORCE SSH: {ip} ({count} tentativas em {SSH_FAIL_WINDOW}s)")
                block_ip(ip, "brute force ssh", port=22)

            elif count >= SSH_MEDIUM_THRESHOLD:
                log_with_cooldown(
                    f"ssh-medium-{ip}",
                    "MEDIUM",
                    f"Tentativas SSH suspeitas: {ip} ({count}/{SSH_HIGH_THRESHOLD})",
                    cooldown=30
                )

            else:
                log_with_cooldown(
                    f"ssh-low-{ip}",
                    "LOW",
                    f"Falha SSH: {ip} ({count}/{SSH_HIGH_THRESHOLD})",
                    cooldown=10
                )

    except Exception as e:
        log_event("LOW", f"Erro em SSH brute force: {e}")


def edr_loop():
    log_event("LOW", "EDR iniciado")

    while True:
        try:
            monitor_ports()
            detect_network_anomaly()
            detect_ssh_bruteforce()
            save_stats()
            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            log_event("LOW", f"Erro no loop principal: {e}")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    configure_firewall()
    configure_ssh()
    edr_loop()
