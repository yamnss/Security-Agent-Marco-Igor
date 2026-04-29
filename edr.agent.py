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
        "blocked_ports": [23,21,80],
        "allowed_ports": [22],
        "check_interval": 5,
        "ssh_medium_threshold": 3,
        "ssh_high_threshold": 6,
        "ssh_fail_window": 300,
        "scan_threshold": 5,
        "scan_window": 30,
        "event_cooldown": 30,
        "whitelist_ips": [],
        "enable_geolocation": False
    }

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                user = json.load(f)
                default.update(user)
    except:
        pass

    return default

CONFIG = load_config()

# -------------------------
# VARS
# -------------------------
CHECK_INTERVAL = CONFIG["check_interval"]
BLOCKED_PORTS = CONFIG["blocked_ports"]
SSH_MEDIUM = CONFIG["ssh_medium_threshold"]
SSH_HIGH = CONFIG["ssh_high_threshold"]
SSH_WINDOW = CONFIG["ssh_fail_window"]

SCAN_THRESHOLD = CONFIG["scan_threshold"]
SCAN_WINDOW = CONFIG["scan_window"]

WHITELIST = CONFIG["whitelist_ips"]

last_auth_pos = 0
last_ufw_pos = 0

ssh_attempts = {}
scan_attempts = {}
blocked_ips = set()

# -------------------------
# LOG
# -------------------------
def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def db_event(level, etype, ip, msg):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
        INSERT INTO events (timestamp, level, event_type, ip, message)
        VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            level, etype, ip, msg
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"[ERRO DB] {e}")

def event(level, msg, etype="GENERAL", ip=None):
    log(f"[{level}] {msg}")
    db_event(level, etype, ip, msg)

# -------------------------
# BLOCK
# -------------------------
def block_ip(ip, reason, port=None):
    if ip in WHITELIST:
        return

    if ip in blocked_ips:
        return

    if port:
        subprocess.run(["ufw","insert","1","deny","from",ip,"to","any","port",str(port)])
    else:
        subprocess.run(["ufw","insert","1","deny","from",ip])

    subprocess.run(["conntrack","-D","-s",ip])
    blocked_ips.add(ip)

    event("HIGH", f"IP bloqueado {ip} motivo={reason}", "IP_BLOCK", ip)

# -------------------------
# SSH DETECT
# -------------------------
def detect_ssh():
    global last_auth_pos

    if not os.path.exists(AUTH_LOG):
        return

    with open(AUTH_LOG) as f:
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

        ssh_attempts.setdefault(ip, [])
        ssh_attempts[ip].append(now)

        ssh_attempts[ip] = [t for t in ssh_attempts[ip] if now - t < SSH_WINDOW]
        count = len(ssh_attempts[ip])

        if count >= SSH_HIGH:
            event("HIGH", f"Brute force {ip}", "SSH_BRUTE_FORCE", ip)
            block_ip(ip, "ssh", 22)

        elif count >= SSH_MEDIUM:
            event("MEDIUM", f"SSH suspeito {ip}", "SSH_SUSPICIOUS", ip)

        else:
            event("LOW", f"Falha SSH {ip}", "SSH_FAILURE", ip)

# -------------------------
# SCAN
# -------------------------
def detect_scan():
    global last_ufw_pos

    if not os.path.exists(UFW_LOG):
        return

    with open(UFW_LOG) as f:
        f.seek(last_ufw_pos)
        lines = f.readlines()
        last_ufw_pos = f.tell()

    now = time.time()

    for line in lines:
        if "BLOCK" not in line:
            continue

        match = re.search(r"SRC=([0-9\.]+)", line)
        if not match:
            continue

        ip = match.group(1)

        scan_attempts.setdefault(ip, [])
        scan_attempts[ip].append(now)

        scan_attempts[ip] = [t for t in scan_attempts[ip] if now - t < SCAN_WINDOW]

        if len(scan_attempts[ip]) >= SCAN_THRESHOLD:
            event("MEDIUM", f"Scan detectado {ip}", "PORT_SCAN", ip)

# -------------------------
# LOOP
# -------------------------
def main():
    event("LOW", "EDR iniciado", "SYSTEM")

    while True:
        detect_ssh()
        detect_scan()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
