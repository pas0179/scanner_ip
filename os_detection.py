"""
Détection avancée des versions d'OS via analyse des bannières de services
"""

import re
import socket
import logging

logger = logging.getLogger(__name__)


def parse_ssh_banner(banner):
    """
    Parse une bannière SSH pour extraire l'OS et sa version

    Exemples:
    - SSH-2.0-OpenSSH_9.2p1 Debian-2+deb13u1 → Debian 13
    - SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 → Ubuntu
    - SSH-2.0-OpenSSH_for_Windows_8.1 → Windows
    """
    if not banner:
        return None

    banner = banner.strip()

    # Debian
    debian_match = re.search(r'Debian.*deb(\d+)', banner, re.IGNORECASE)
    if debian_match:
        version = debian_match.group(1)
        return f"Debian {version}"

    if 'debian' in banner.lower():
        return "Debian"

    # Ubuntu
    ubuntu_match = re.search(r'Ubuntu[- ](\d+\.\d+)', banner, re.IGNORECASE)
    if ubuntu_match:
        version = ubuntu_match.group(1)
        return f"Ubuntu {version}"

    if 'ubuntu' in banner.lower():
        return "Ubuntu"

    # Windows
    if 'windows' in banner.lower():
        return "Windows Server"

    # Red Hat / CentOS / Fedora
    if any(x in banner.lower() for x in ['redhat', 'rhel', 'centos', 'fedora']):
        return "Red Hat/CentOS"

    # FreeBSD
    freebsd_match = re.search(r'FreeBSD[- ](\d+\.\d+)', banner, re.IGNORECASE)
    if freebsd_match:
        version = freebsd_match.group(1)
        return f"FreeBSD {version}"

    if 'freebsd' in banner.lower():
        return "FreeBSD"

    # Générique OpenSSH
    openssh_match = re.search(r'OpenSSH[_\s](\d+\.\d+)', banner)
    if openssh_match:
        return f"Linux/Unix (OpenSSH {openssh_match.group(1)})"

    return None


def parse_http_banner(banner):
    """
    Parse une bannière HTTP pour extraire l'OS

    Exemples:
    - Server: Apache/2.4.57 (Debian) → Debian
    - Server: nginx/1.18.0 (Ubuntu) → Ubuntu
    - Server: Microsoft-IIS/10.0 → Windows Server
    """
    if not banner:
        return None

    banner = banner.strip()

    # Debian
    if 'debian' in banner.lower():
        debian_match = re.search(r'Debian.*?(\d+)', banner, re.IGNORECASE)
        if debian_match:
            return f"Debian {debian_match.group(1)}"
        return "Debian"

    # Ubuntu
    ubuntu_match = re.search(r'Ubuntu.*?(\d+\.\d+)', banner, re.IGNORECASE)
    if ubuntu_match:
        return f"Ubuntu {ubuntu_match.group(1)}"

    if 'ubuntu' in banner.lower():
        return "Ubuntu"

    # Windows
    if 'microsoft-iis' in banner.lower() or 'windows' in banner.lower():
        iis_match = re.search(r'IIS[/\s](\d+\.\d+)', banner, re.IGNORECASE)
        if iis_match:
            iis_version = float(iis_match.group(1))
            if iis_version >= 10.0:
                return "Windows Server 2016+"
            elif iis_version >= 8.5:
                return "Windows Server 2012 R2"
            elif iis_version >= 8.0:
                return "Windows Server 2012"
            else:
                return "Windows Server"
        return "Windows Server"

    # CentOS / Red Hat
    if any(x in banner.lower() for x in ['centos', 'rhel', 'redhat']):
        centos_match = re.search(r'CentOS.*?(\d+)', banner, re.IGNORECASE)
        if centos_match:
            return f"CentOS {centos_match.group(1)}"
        return "CentOS/RHEL"

    # Fedora
    if 'fedora' in banner.lower():
        fedora_match = re.search(r'Fedora.*?(\d+)', banner, re.IGNORECASE)
        if fedora_match:
            return f"Fedora {fedora_match.group(1)}"
        return "Fedora"

    # FreeBSD
    if 'freebsd' in banner.lower():
        return "FreeBSD"

    # Android (serveurs web embarqués)
    if 'android' in banner.lower():
        android_match = re.search(r'Android[/\s](\d+)', banner, re.IGNORECASE)
        if android_match:
            return f"Android {android_match.group(1)}"
        return "Android"

    return None


def parse_ftp_banner(banner):
    """
    Parse une bannière FTP

    Exemples:
    - 220 ProFTPD 1.3.6 Server (Debian) → Debian
    - 220 Microsoft FTP Service → Windows
    """
    if not banner:
        return None

    banner = banner.strip()

    if 'debian' in banner.lower():
        return "Debian"

    if 'ubuntu' in banner.lower():
        return "Ubuntu"

    if 'microsoft' in banner.lower() or 'windows' in banner.lower():
        return "Windows Server"

    return None


def parse_smb_banner(banner):
    """
    Parse les informations SMB/Samba
    """
    if not banner:
        return None

    banner = banner.strip()

    # Samba indique souvent un système Linux
    if 'samba' in banner.lower():
        return "Linux (Samba)"

    # Windows
    if 'windows' in banner.lower():
        # Essayer de détecter la version
        if 'windows 10' in banner.lower():
            return "Windows 10/11"
        elif 'windows 8' in banner.lower():
            return "Windows 8/8.1"
        elif 'windows 7' in banner.lower():
            return "Windows 7"
        elif 'server 2019' in banner.lower():
            return "Windows Server 2019"
        elif 'server 2016' in banner.lower():
            return "Windows Server 2016"
        elif 'server 2012' in banner.lower():
            return "Windows Server 2012"
        else:
            return "Windows"

    return None


def detect_os_from_banners(banners_dict):
    """
    Analyse toutes les bannières collectées pour déterminer l'OS

    Args:
        banners_dict: Dict {port: banner_text}

    Returns:
        Version d'OS détectée ou None
    """
    os_candidates = []

    for port, banner in banners_dict.items():
        if not banner:
            continue

        detected_os = None

        # SSH (port 22)
        if port == 22:
            detected_os = parse_ssh_banner(banner)

        # HTTP/HTTPS (ports 80, 443, 8080, 8443, etc.)
        elif port in [80, 443, 8000, 8080, 8443, 8888]:
            detected_os = parse_http_banner(banner)

        # FTP (port 21)
        elif port == 21:
            detected_os = parse_ftp_banner(banner)

        # SMB (port 445)
        elif port == 445:
            detected_os = parse_smb_banner(banner)

        # Fallback: chercher des patterns génériques dans toutes les bannières
        else:
            for parser in [parse_ssh_banner, parse_http_banner, parse_ftp_banner]:
                detected_os = parser(banner)
                if detected_os:
                    break

        if detected_os:
            os_candidates.append((detected_os, port))
            logger.debug(f"OS détecté sur port {port}: {detected_os}")

    if not os_candidates:
        return None

    # Prioriser SSH > HTTP > FTP > Autres
    priority_ports = {22: 3, 80: 2, 443: 2, 21: 1}

    os_candidates.sort(key=lambda x: priority_ports.get(x[1], 0), reverse=True)

    # Retourner le meilleur candidat
    best_os = os_candidates[0][0]

    # Si on a plusieurs détections cohérentes, on peut être plus confiant
    if len(os_candidates) > 1:
        # Vérifier si plusieurs détections pointent vers le même OS
        os_names = [os.split()[0] for os, _ in os_candidates]  # Extraire "Debian" de "Debian 13"
        if all(name == os_names[0] for name in os_names):
            # Toutes les détections concordent, retourner la plus précise
            most_detailed = max(os_candidates, key=lambda x: len(x[0]))
            return most_detailed[0]

    return best_os


def grab_banner(ip, port, timeout=3):
    """
    Récupère une bannière de service de manière optimisée

    Args:
        ip: Adresse IP
        port: Port du service
        timeout: Timeout en secondes

    Returns:
        Bannière du service ou None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Pour SSH et FTP, la bannière arrive automatiquement
        if port in [21, 22]:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner

        # Pour HTTP, envoyer une requête GET
        if port in [80, 443, 8000, 8080, 8443, 8888]:
            request = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
            sock.send(request)
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()

            # Extraire le header Server
            server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
            if server_match:
                return server_match.group(1).strip()

            return response[:200]  # Retourner le début de la réponse

        # Pour les autres ports, essayer de recevoir
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner if banner else None

    except Exception as e:
        logger.debug(f"Erreur récupération bannière {ip}:{port}: {e}")
        return None
