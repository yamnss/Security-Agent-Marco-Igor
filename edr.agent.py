#!/usr/bin/env python3

import os
import re
import json
import time
import psutil
import sqlite3
import subprocess
from datetime import datetime

# -------------------------
# PATHS
# -------------------------
LOG_FILE = "/var/log/edr_agent.log"
DB_FILE = "/opt/edr-agent/edr.db"
CONFIG_FILE = "/opt/edr-agent/config.json"

AUTH_LOG = "/var/log/auth.log"
UFW_LOG = "/var/log/ufw.log"

# -------------------------
# LOAD CONFIG
# -------------------------
def load_config():
    default = {
        "blocked_ports": [23, 21, 80],
        "allowed_ports": [22],
        "check_interval": 5,
        "ssh_medium_threshold": 3,
        "ssh_high_threshold": 6,
        "ssh_fail_window": 300,
        "scan_threshold": 5,
        "scan_window": 30,
        "event_cooldown": 30,
        "whitelist_ips": [],
        "enable_geolocation": False,
        "allowed_countries": ["BR"]
    }

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                default.update(user_config)
    except Exception as e:
        print(f"Erro ao carregar config: {e}")

    return default


CONFIG = load_config()

# -------------------------
# VARS
# -------------------------
CHECK_INTERVAL = CONFIG["check_interval"]

BLOCKED_PORTS = CONFIG["blocked_ports"]
ALLOWED_PORTS = CONFIG["allowed_ports"]

SSH_MEDIUM = CONFIG["ssh_medium_threshold"]
SSH_HIGH = CONFIG["ssh_high_threshold"]
SSH_WINDOW = CONFIG["ssh_fail_window"]

SCAN_THRESHOLD = CONFIG["scan_threshold"]
SCAN_WINDOW = CONFIG["scan_window"]
EVENT_COOLDOWN = CONFIG["event_cooldown"]

WHITELIST = CONFIG["whitelist_ips"]

last_auth_pos = 0
last_ufw_pos = 0

ssh_attempts = {}
scan_attempts = {}
blocked_ips = set()
last_event_log = {}

# -------------------------
# LOG
# -------------------------
def ensure_runtime_files():
    try:
        os.makedirs("/opt/edr-agent", exist_ok=True)

        if not os.path.exists(LOG_FILE):
            open(LOG_FILE, "a").close()

        if not os.path.exists(UFW_LOG):
            open(UFW_LOG, "a").close()

    except Exception:
        pass


def log(msg):
    ensure_runtime_files()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        f.flush()


def db_event(level, etype, ip, msg):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            level TEXT,
            event_type TEXT,
            ip TEXT,
            message TEXT
        )
        """)

        c.execute("""
        INSERT INTO events (timestamp, level, event_type, ip, message)
        VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            level,
            etype,
            ip,
            msg
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        log(f"[ERRO DB] {e}")


def event(level, msg, etype="GENERAL", ip=None):
    log(f"[{level}] {msg}")
    db_event(level, etype, ip, msg)


def event_cooldown(key, level, msg, etype="GENERAL", ip=None, cooldown=None):
    if cooldown is None:
        cooldown = EVENT_COOLDOWN

    now = time.time()
    last = last_event_log.get(key, 0)

    if now - last >= cooldown:
        event(level, msg, etype, ip)
        last_event_log[key] = now


# -------------------------
# SAFE RUN
# -------------------------
def safe_run(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        event("LOW", f"Falha ao executar comando {' '.join(cmd)}: {e}", "SYSTEM_ERROR")


def safe_output(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout or ""
    except Exception:
        return ""


# -------------------------
# FIREWALL
# -------------------------
def configure_firewall():
    event("LOW", "Configurando firewall via config.json", "FIREWALL")

    safe_run(["systemctl", "enable", "--now", "rsyslog"])
    safe_run(["ufw", "--force", "enable"])
    safe_run(["ufw", "logging", "on"])

    for port in ALLOWED_PORTS:
        safe_run(["ufw", "allow", f"{port}/tcp"])
        event_cooldown(
            f"fw-allow-{port}",
            "LOW",
            f"Porta permitida via config: {port}/tcp",
            "FIREWALL",
            cooldown=3600
        )

    for port in BLOCKED_PORTS:
        safe_run(["ufw", "deny", f"{port}/tcp"])
        event_cooldown(
            f"fw-deny-{port}",
            "LOW",
            f"Porta bloqueada via config: {port}/tcp",
            "FIREWALL",
            cooldown=3600
        )


# -------------------------
# SSH CONFIG
# -------------------------
def ensure_sshd_option(content, key, value):
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.MULTILINE)

    if pattern.search(content):
        return pattern.sub(f"{key} {value}", content)

    if not content.endswith("\n"):
        content += "\n"

    return content + f"{key} {value}\n"


def configure_ssh():
    ssh_config = "/etc/ssh/sshd_config"

    if not os.path.exists(ssh_config):
        event("MEDIUM", "sshd_config não encontrado; hardening SSH ignorado", "SSH_CONFIG")
        return

    try:
        with open(ssh_config, "r", encoding="utf-8") as f:
            content = f.read()

        updated = ensure_sshd_option(content, "MaxAuthTries", str(SSH_HIGH))
        updated = ensure_sshd_option(updated, "PermitRootLogin", "no")

        if updated != content:
            with open(ssh_config, "w", encoding="utf-8") as f:
                f.write(updated)

            event("LOW", "Configurações SSH atualizadas", "SSH_CONFIG")

        safe_run(["systemctl", "restart", "ssh"])

    except Exception as e:
        event("MEDIUM", f"Erro ao configurar SSH: {e}", "SSH_CONFIG_ERROR")


# -------------------------
# HELPERS
# -------------------------
def is_whitelisted(ip):
    return ip in WHITELIST


def ufw_rule_exists(ip, port=None):
    status = safe_output(["ufw", "status"])

    if port is None:
        return ip in status

    return ip in status and str(port) in status


# -------------------------
# BLOCK
# -------------------------
def block_ip(ip, reason, port=None):
    if is_whitelisted(ip):
        event("LOW", f"IP em whitelist, bloqueio ignorado: {ip}", "WHITELIST", ip)
        return

    if ip in blocked_ips:
        return

    if ufw_rule_exists(ip, port):
        blocked_ips.add(ip)
        return

    if port:
        safe_run(["ufw", "insert", "1", "deny", "from", ip, "to", "any", "port", str(port)])
    else:
        safe_run(["ufw", "insert", "1", "deny", "from", ip])

    safe_run(["conntrack", "-D", "-s", ip])

    blocked_ips.add(ip)
    event("HIGH", f"IP bloqueado {ip} motivo={reason}", "IP_BLOCK", ip)


# -------------------------
# PORT MONITOR
# -------------------------
def monitor_ports():
    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if not conn.raddr:
                continue

            if conn.status not in ("ESTABLISHED", "SYN_RECV"):
                continue

            ip = conn.raddr.ip
            port = conn.laddr.port

            if is_whitelisted(ip):
                continue

            if port == 22:
                event_cooldown(
                    f"ssh-conn-{ip}",
                    "LOW",
                    f"Conexão SSH detectada de {ip}",
                    "SSH_CONNECTION",
                    ip,
                    cooldown=15
                )

            if port in BLOCKED_PORTS:
                event("HIGH", f"Acesso proibido {ip}:{port}", "PORT_ABUSE", ip)
                block_ip(ip, "porta proibida", port)

    except Exception as e:
        event("LOW", f"Erro em monitor_ports: {e}", "SYSTEM_ERROR")


# -------------------------
# SSH DETECT
# -------------------------
def detect_ssh():
    global last_auth_pos

    if not os.path.exists(AUTH_LOG):
        event_cooldown(
            "auth-log-missing",
            "MEDIUM",
            f"Arquivo {AUTH_LOG} não encontrado",
            "SYSTEM",
            cooldown=300
        )
        return

    try:
        with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_auth_pos)
            lines = f.readlines()
            last_auth_pos = f.tell()

        now = time.time()

        for line in lines:
            if "Failed password" not in line:
                continue

            match = re.search(r"from ([0-9\.]+)", line)
            if not match:
                continue

            ip = match.group(1)

            if is_whitelisted(ip):
                event("LOW", f"Falha SSH ignorada para IP em whitelist: {ip}", "WHITELIST", ip)
                continue

            ssh_attempts.setdefault(ip, [])
            ssh_attempts[ip].append(now)
            ssh_attempts[ip] = [t for t in ssh_attempts[ip] if now - t < SSH_WINDOW]

            count = len(ssh_attempts[ip])

            if count >= SSH_HIGH:
                event("HIGH", f"Brute force SSH detectado {ip} ({count}/{SSH_HIGH})", "SSH_BRUTE_FORCE", ip)
                block_ip(ip, "ssh brute force", 22)

            elif count >= SSH_MEDIUM:
                event_cooldown(
                    f"ssh-med-{ip}",
                    "MEDIUM",
                    f"SSH suspeito {ip} ({count}/{SSH_HIGH})",
                    "SSH_SUSPICIOUS",
                    ip,
                    cooldown=30
                )

            else:
                event_cooldown(
                    f"ssh-low-{ip}",
                    "LOW",
                    f"Falha SSH {ip} ({count}/{SSH_HIGH})",
                    "SSH_FAILURE",
                    ip,
                    cooldown=10
                )

    except Exception as e:
        event("LOW", f"Erro em detect_ssh: {e}", "SYSTEM_ERROR")


# -------------------------
# SCAN DETECT
# -------------------------
def detect_scan():
    global last_ufw_pos

    if not os.path.exists(UFW_LOG):
        event_cooldown(
            "ufw-log-missing",
            "MEDIUM",
            f"Arquivo {UFW_LOG} não encontrado",
            "SYSTEM",
            cooldown=300
        )
        return

    try:
        with open(UFW_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_ufw_pos)
            lines = f.readlines()
            last_ufw_pos = f.tell()

        now = time.time()

        for line in lines:
            if "BLOCK" not in line or "SRC=" not in line:
                continue

            match = re.search(r"SRC=([0-9\.]+)", line)
            if not match:
                continue

            ip = match.group(1)

            if is_whitelisted(ip):
                continue

            scan_attempts.setdefault(ip, [])
            scan_attempts[ip].append(now)
            scan_attempts[ip] = [t for t in scan_attempts[ip] if now - t < SCAN_WINDOW]

            count = len(scan_attempts[ip])

            if count >= SCAN_THRESHOLD:
                event_cooldown(
                    f"scan-{ip}",
                    "MEDIUM",
                    f"Scan detectado {ip} ({count} tentativas em {SCAN_WINDOW}s)",
                    "PORT_SCAN",
                    ip,
                    cooldown=SCAN_WINDOW
                )

    except Exception as e:
        event("LOW", f"Erro em detect_scan: {e}", "SYSTEM_ERROR")


# -------------------------
# LOOP
# -------------------------
def main():
    ensure_runtime_files()
    event("LOW", "EDR iniciado", "SYSTEM")

    while True:
        monitor_ports()
        detect_ssh()
        detect_scan()
        time.sleep(CHECK_INTERVAL)


# -------------------------
# START
# -------------------------
if __name__ == "__main__":
    ensure_runtime_files()
    configure_firewall()
    configure_ssh()
    main()
