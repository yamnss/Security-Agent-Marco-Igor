#!/usr/bin/env python3

import os
import re
import subprocess
import time
from datetime import datetime

import psutil

LOG_FILE = "/var/log/edr_agent.log"
SSH_CONFIG = "/etc/ssh/sshd_config"
AUTH_LOG = "/var/log/auth.log"
UFW_LOG = "/var/log/ufw.log"

BLOCKED_PORTS = [23, 21, 80]
ALLOWED_PORTS = [22]

CHECK_INTERVAL = 5
EVENT_COOLDOWN = 30          # segundos para repetir log do mesmo evento
SCAN_WINDOW = 30             # janela para contar tentativas de scan
SCAN_THRESHOLD = 5           # tentativas bloqueadas no ufw para alertar
SSH_FAIL_WINDOW = 300        # janela para contar falhas de ssh (5 min)
SSH_FAIL_THRESHOLD = 3       # 3 senhas erradas = bloqueio

# estado em memória
last_auth_position = 0
last_ufw_position = 0

last_event_log = {}          # chave -> timestamp do último log
ssh_failures = {}            # ip -> [timestamps]
scan_attempts = {}           # ip -> [timestamps]


# -------------------------
# LOG
# -------------------------
def log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")
        f.flush()


def log_with_cooldown(event_key: str, message: str, cooldown: int = EVENT_COOLDOWN) -> None:
    now = time.time()
    last = last_event_log.get(event_key, 0)

    if now - last >= cooldown:
        log(message)
        last_event_log[event_key] = now


# -------------------------
# SAFE RUN
# -------------------------
def safe_run(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        log(f"[ERRO] comando falhou {' '.join(cmd)}: {e}")


def safe_run_output(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout or ""
    except Exception as e:
        log(f"[ERRO] saída do comando falhou {' '.join(cmd)}: {e}")
        return ""


# -------------------------
# HELPERS FIREWALL
# -------------------------
def ufw_rule_exists(ip: str, port: int | None = None) -> bool:
    status = safe_run_output(["ufw", "status"])
    if not status:
        return False

    if port is None:
        patterns = [
            f"DENY IN {ip}",
            f"DENY       {ip}",
            f"DENY IN    {ip}",
        ]
    else:
        patterns = [
            f"{port} DENY IN {ip}",
            f"{port}/tcp DENY IN {ip}",
            f"{port}                         DENY IN    {ip}",
            f"{port}/tcp                     DENY IN    {ip}",
            f"DENY IN    {ip}",
        ]

    return any(p in status for p in patterns)


def block_ip(ip: str, reason: str, port: int | None = None) -> None:
    if ufw_rule_exists(ip, port):
        log_with_cooldown(
            f"rule-exists:{ip}:{port}",
            f"[INFO] Regra já existente para {ip}" + (f" na porta {port}" if port else ""),
            cooldown=60
        )
        return

    if port is None:
        safe_run(["ufw", "insert", "1", "deny", "from", ip])
    else:
        safe_run(["ufw", "insert", "1", "deny", "from", ip, "to", "any", "port", str(port)])

    # tenta derrubar conexões já existentes
    safe_run(["conntrack", "-D", "-s", ip])

    log(f"[ACTION] IP bloqueado: {ip} | motivo: {reason}" + (f" | porta: {port}" if port else ""))


# -------------------------
# FIREWALL
# -------------------------
def configure_firewall() -> None:
    log("[STARTUP] Configurando firewall")

    safe_run(["ufw", "--force", "enable"])
    safe_run(["ufw", "logging", "on"])

    current_status = safe_run_output(["ufw", "status"])

    for port in BLOCKED_PORTS:
        if f"{port}" not in current_status:
            safe_run(["ufw", "deny", str(port)])
        log_with_cooldown(f"fw-block:{port}", f"[INFO] Porta bloqueada: {port}", cooldown=3600)

    for port in ALLOWED_PORTS:
        if f"{port}" not in current_status:
            safe_run(["ufw", "allow", str(port)])
        log_with_cooldown(f"fw-allow:{port}", f"[INFO] Porta permitida: {port}", cooldown=3600)


# -------------------------
# SSH HARDENING
# -------------------------
def ensure_sshd_option(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.MULTILINE)

    if pattern.search(content):
        return pattern.sub(f"{key} {value}", content)

    if not content.endswith("\n"):
        content += "\n"

    return content + f"{key} {value}\n"


def configure_ssh() -> None:
    if not os.path.exists(SSH_CONFIG):
        log("[WARNING] sshd_config não encontrado; pulando hardening SSH")
        return

    log("[STARTUP] Aplicando políticas SSH")

    try:
        with open(SSH_CONFIG, "r", encoding="utf-8") as f:
            content = f.read()

        updated = ensure_sshd_option(content, "MaxAuthTries", "6")
        updated = ensure_sshd_option(updated, "PermitRootLogin", "no")

        if updated != content:
            with open(SSH_CONFIG, "w", encoding="utf-8") as f:
                f.write(updated)
            log("[INFO] Configurações SSH atualizadas")

        safe_run(["systemctl", "restart", "ssh"])

    except Exception as e:
        log(f"[ERRO] configure_ssh: {e}")


# -------------------------
# MONITORAMENTO DE PORTAS
# -------------------------
def monitor_ports() -> None:
    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if not conn.raddr:
                continue

            if conn.status not in ("ESTABLISHED", "SYN_RECV"):
                continue

            local_port = conn.laddr.port
            remote_ip = conn.raddr.ip

            # Loga conexões SSH, mas com cooldown por IP
            if local_port == 22:
                log_with_cooldown(
                    event_key=f"ssh-conn:{remote_ip}",
                    message=f"[INFO] Conexão SSH detectada de {remote_ip}",
                    cooldown=15
                )

            # Se alguém conseguir atingir uma porta sensível, loga e bloqueia
            if local_port in BLOCKED_PORTS:
                log_with_cooldown(
                    event_key=f"blocked-port:{remote_ip}:{local_port}",
                    message=f"[CRITICAL] Acesso proibido: {remote_ip} -> porta {local_port}",
                    cooldown=10
                )
                block_ip(remote_ip, reason="acesso a porta sensível", port=local_port)

    except Exception as e:
        log(f"[ERRO] monitor_ports: {e}")


# -------------------------
# DETECÇÃO DE SCAN
# -------------------------
def detect_network_anomaly() -> None:
    global last_ufw_position

    if not os.path.exists(UFW_LOG):
        log_with_cooldown("ufw-log-missing", f"[WARNING] Arquivo {UFW_LOG} não encontrado", cooldown=300)
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

            if ip not in scan_attempts:
                scan_attempts[ip] = []

            scan_attempts[ip].append(now)
            scan_attempts[ip] = [ts for ts in scan_attempts[ip] if now - ts <= SCAN_WINDOW]

            count = len(scan_attempts[ip])

            if count >= SCAN_THRESHOLD:
                log_with_cooldown(
                    event_key=f"scan:{ip}",
                    message=f"[WARNING] SCAN detectado: {ip} ({count} tentativas em {SCAN_WINDOW}s)",
                    cooldown=SCAN_WINDOW
                )

    except Exception as e:
        log(f"[ERRO] network anomaly: {e}")


# -------------------------
# DETECÇÃO SSH BRUTE FORCE
# -------------------------
def detect_ssh_bruteforce() -> None:
    global last_auth_position

    if not os.path.exists(AUTH_LOG):
        log_with_cooldown("auth-log-missing", f"[WARNING] Arquivo {AUTH_LOG} não encontrado", cooldown=300)
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

            if ip not in ssh_failures:
                ssh_failures[ip] = []

            ssh_failures[ip].append(now)
            ssh_failures[ip] = [ts for ts in ssh_failures[ip] if now - ts <= SSH_FAIL_WINDOW]

            count = len(ssh_failures[ip])

            log_with_cooldown(
                event_key=f"ssh-fail-log:{ip}",
                message=f"[INFO] Falhas SSH detectadas de {ip} ({count}/{SSH_FAIL_THRESHOLD})",
                cooldown=10
            )

            if count >= SSH_FAIL_THRESHOLD:
                log_with_cooldown(
                    event_key=f"ssh-bruteforce:{ip}",
                    message=f"[CRITICAL] BRUTE FORCE SSH: {ip} ({count} tentativas em {SSH_FAIL_WINDOW}s)",
                    cooldown=SSH_FAIL_WINDOW
                )
                block_ip(ip, reason="brute force ssh", port=22)

    except Exception as e:
        log(f"[ERRO] SSH brute force: {e}")


# -------------------------
# LOOP PRINCIPAL
# -------------------------
def edr_loop() -> None:
    log("[START] EDR iniciado")

    while True:
        try:
            monitor_ports()
            detect_network_anomaly()
            detect_ssh_bruteforce()

            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            log(f"[ERRO LOOP] {e}")
            time.sleep(CHECK_INTERVAL)


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    configure_firewall()
    configure_ssh()
    edr_loop()
