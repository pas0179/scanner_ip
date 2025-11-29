"""
Configuration du Scanner IP
"""

import os
from pathlib import Path

# Répertoires
BASE_DIR = Path(__file__).parent
EXPORT_DIR = BASE_DIR / "exports"
HISTORY_DIR = BASE_DIR / "history"
LOG_DIR = BASE_DIR / "logs"

# Créer les répertoires s'ils n'existent pas
for directory in [EXPORT_DIR, HISTORY_DIR, LOG_DIR]:
    directory.mkdir(exist_ok=True)

# Configuration du scan (optimisé pour vitesse)
DEFAULT_TIMEOUT = 0.5  # secondes (réduit de 1s à 0.5s)
PING_TIMEOUT = 0.3  # secondes pour le ping (réduit de 0.5s à 0.3s)
MAX_THREADS = 200  # nombre maximum de threads pour le scan (augmenté de 100 à 200)

# Ports communs à scanner
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP-Alt
    8443,  # HTTPS-Alt
]

# Ports étendus (pour scan approfondi)
EXTENDED_PORTS = list(range(1, 1024))  # Tous les ports well-known

# Services connus
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MS-SQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Interface graphique
WINDOW_TITLE = "Scanner IP Local - Analyse Réseau"
WINDOW_SIZE = "1400x800"
THEME_COLOR = "#2c3e50"
ACCENT_COLOR = "#3498db"
SUCCESS_COLOR = "#27ae60"
WARNING_COLOR = "#e67e22"
ERROR_COLOR = "#e74c3c"

# Export
DEFAULT_EXPORT_FORMAT = "csv"  # csv, json, xml, html
EXPORT_FORMATS = ["csv", "json", "xml", "html"]

# Historique
MAX_HISTORY_ENTRIES = 100
AUTO_SAVE_HISTORY = True

# Scan types
SCAN_TYPES = {
    "quick": {
        "name": "Scan Rapide",
        "ping": True,
        "ports": False,
        "os_detection": False,
        "mac_address": True,
        "timeout": 0.5
    },
    "normal": {
        "name": "Scan Normal",
        "ping": True,
        "ports": True,
        "port_list": COMMON_PORTS,
        "os_detection": False,
        "mac_address": True,
        "timeout": 1
    },
    "deep": {
        "name": "Scan Approfondi",
        "ping": True,
        "ports": True,
        "port_list": EXTENDED_PORTS,
        "os_detection": True,
        "mac_address": True,
        "service_detection": True,
        "timeout": 2
    },
    "custom": {
        "name": "Scan Personnalisé",
        "ping": True,
        "ports": True,
        "port_list": [],
        "os_detection": False,
        "mac_address": True,
        "timeout": 1
    }
}

# Détection OS (basique, via TTL)
OS_TTL_SIGNATURES = {
    64: "Linux/Unix",
    128: "Windows",
    255: "Cisco/Network Device",
    254: "Solaris/AIX"
}

# Logging
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = LOG_DIR / "scanner.log"

# Sudo configuration
REQUIRE_SUDO_FOR_ADVANCED = True  # Nécessite sudo pour scan ARP et certains scans
SUDO_WARNING_MESSAGE = "Certaines fonctionnalités nécessitent des privilèges root (sudo). Relancez avec sudo pour activer toutes les fonctionnalités."
