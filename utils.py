"""
Utilitaires pour le Scanner IP
"""

import ipaddress
import socket
import struct
import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import os
import netifaces

from config import EXPORT_DIR, PORT_SERVICES


def get_local_ip() -> str:
    """
    Récupère l'adresse IP locale de la machine
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_default_gateway() -> Optional[str]:
    """
    Récupère la passerelle par défaut
    """
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    except Exception:
        return None


def get_network_range(ip: str = None, netmask: str = "255.255.255.0") -> str:
    """
    Calcule la plage réseau à partir d'une IP et d'un masque

    Args:
        ip: Adresse IP (si None, utilise l'IP locale)
        netmask: Masque de sous-réseau

    Returns:
        Plage réseau au format CIDR (ex: 192.168.1.0/24)
    """
    if ip is None:
        ip = get_local_ip()

    try:
        # Convertir le masque en CIDR
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return str(network)
    except Exception as e:
        return "192.168.1.0/24"  # Valeur par défaut


def validate_ip(ip: str) -> bool:
    """
    Valide une adresse IP

    Args:
        ip: Adresse IP à valider

    Returns:
        True si l'IP est valide, False sinon
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_network(network: str) -> bool:
    """
    Valide une plage réseau CIDR

    Args:
        network: Plage réseau au format CIDR

    Returns:
        True si la plage est valide, False sinon
    """
    try:
        ipaddress.IPv4Network(network, strict=False)
        return True
    except ValueError:
        return False


def cidr_to_ip_list(network: str) -> List[str]:
    """
    Convertit une plage CIDR en liste d'IPs

    Args:
        network: Plage réseau au format CIDR

    Returns:
        Liste des adresses IP
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return []


def get_hostname(ip: str, timeout: float = 1.0) -> str:
    """
    Récupère le nom d'hôte à partir d'une IP

    Args:
        ip: Adresse IP
        timeout: Timeout en secondes

    Returns:
        Nom d'hôte ou IP si non trouvé
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return ip


def get_service_name(port: int) -> str:
    """
    Récupère le nom du service associé à un port

    Args:
        port: Numéro de port

    Returns:
        Nom du service ou "Unknown"
    """
    return PORT_SERVICES.get(port, f"Port {port}")


def format_mac_address(mac: str) -> str:
    """
    Formate une adresse MAC

    Args:
        mac: Adresse MAC

    Returns:
        Adresse MAC formatée (XX:XX:XX:XX:XX:XX)
    """
    if not mac or mac == "N/A":
        return "N/A"

    mac = mac.replace(":", "").replace("-", "").upper()
    return ":".join([mac[i:i+2] for i in range(0, 12, 2)])


def is_root() -> bool:
    """
    Vérifie si le script est exécuté avec les privilèges root

    Returns:
        True si root, False sinon
    """
    return os.geteuid() == 0


def export_to_csv(data: List[Dict], filename: str = None) -> str:
    """
    Exporte les données en CSV

    Args:
        data: Liste des résultats de scan
        filename: Nom du fichier (généré automatiquement si None)

    Returns:
        Chemin du fichier créé
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.csv"

    filepath = EXPORT_DIR / filename

    if not data:
        return str(filepath)

    fieldnames = data[0].keys()

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return str(filepath)


def export_to_json(data: List[Dict], filename: str = None) -> str:
    """
    Exporte les données en JSON

    Args:
        data: Liste des résultats de scan
        filename: Nom du fichier (généré automatiquement si None)

    Returns:
        Chemin du fichier créé
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.json"

    filepath = EXPORT_DIR / filename

    export_data = {
        "scan_date": datetime.now().isoformat(),
        "total_hosts": len(data),
        "results": data
    }

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    return str(filepath)


def export_to_xml(data: List[Dict], filename: str = None) -> str:
    """
    Exporte les données en XML

    Args:
        data: Liste des résultats de scan
        filename: Nom du fichier (généré automatiquement si None)

    Returns:
        Chemin du fichier créé
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.xml"

    filepath = EXPORT_DIR / filename

    root = ET.Element("scan_results")
    root.set("date", datetime.now().isoformat())
    root.set("total_hosts", str(len(data)))

    for item in data:
        host = ET.SubElement(root, "host")
        for key, value in item.items():
            elem = ET.SubElement(host, key)
            elem.text = str(value) if value is not None else ""

    tree = ET.ElementTree(root)
    tree.write(filepath, encoding='utf-8', xml_declaration=True)

    return str(filepath)


def export_to_html(data: List[Dict], filename: str = None) -> str:
    """
    Exporte les données en HTML

    Args:
        data: Liste des résultats de scan
        filename: Nom du fichier (généré automatiquement si None)

    Returns:
        Chemin du fichier créé
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.html"

    filepath = EXPORT_DIR / filename

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Résultats du Scan - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #2c3e50;
        }}
        .info {{
            background-color: #fff;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .online {{
            color: #27ae60;
            font-weight: bold;
        }}
        .offline {{
            color: #e74c3c;
        }}
    </style>
</head>
<body>
    <h1>Résultats du Scan Réseau</h1>
    <div class="info">
        <strong>Date du scan:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
        <strong>Nombre d'hôtes détectés:</strong> {len(data)}
    </div>
    <table>
        <thead>
            <tr>
"""

    if data:
        for key in data[0].keys():
            html_content += f"                <th>{key.replace('_', ' ').title()}</th>\n"
        html_content += "            </tr>\n        </thead>\n        <tbody>\n"

        for item in data:
            html_content += "            <tr>\n"
            for value in item.values():
                status_class = "online" if value == "Online" else ""
                html_content += f"                <td class='{status_class}'>{value if value is not None else 'N/A'}</td>\n"
            html_content += "            </tr>\n"

    html_content += """        </tbody>
    </table>
</body>
</html>"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return str(filepath)


def export_data(data: List[Dict], format: str = "csv", filename: str = None) -> str:
    """
    Exporte les données dans le format spécifié

    Args:
        data: Liste des résultats de scan
        format: Format d'export (csv, json, xml, html)
        filename: Nom du fichier

    Returns:
        Chemin du fichier créé
    """
    exporters = {
        "csv": export_to_csv,
        "json": export_to_json,
        "xml": export_to_xml,
        "html": export_to_html
    }

    exporter = exporters.get(format.lower(), export_to_csv)
    return exporter(data, filename)


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse une chaîne de ports (ex: "80,443,8000-8010")

    Args:
        port_string: Chaîne de ports

    Returns:
        Liste de numéros de ports
    """
    ports = []

    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(list(set(ports)))


def format_scan_duration(seconds: float) -> str:
    """
    Formate une durée en secondes en format lisible

    Args:
        seconds: Durée en secondes

    Returns:
        Durée formatée (ex: "2m 30s" ou "45s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
