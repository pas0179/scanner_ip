"""
Classe principale pour le scan IP
"""

import socket
import subprocess
import platform
import re
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP
import logging

from config import (
    DEFAULT_TIMEOUT, PING_TIMEOUT, MAX_THREADS,
    COMMON_PORTS, EXTENDED_PORTS, PORT_SERVICES, OS_TTL_SIGNATURES
)
from utils import (
    validate_ip, validate_network, cidr_to_ip_list,
    get_hostname, get_service_name, is_root
)
from mac_vendors import get_vendor_from_mac, detect_device_type
from os_detection import detect_os_from_banners, grab_banner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IPScanner:
    """
    Classe pour scanner le réseau local
    """

    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialise le scanner

        Args:
            callback: Fonction de callback pour les mises à jour de progression
        """
        self.callback = callback
        self.is_running = False
        self.has_root = is_root()
        self.results = []

    def _update_progress(self, message: str, progress: int = 0):
        """
        Met à jour la progression via le callback

        Args:
            message: Message de progression
            progress: Pourcentage de progression (0-100)
        """
        if self.callback:
            self.callback(message, progress)

    def ping_host(self, ip: str, timeout: float = PING_TIMEOUT) -> Dict:
        """
        Ping une adresse IP (méthode système)

        Args:
            ip: Adresse IP à pinger
            timeout: Timeout en secondes

        Returns:
            Dictionnaire avec les résultats du ping
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

        command = ['ping', param, '1', timeout_param, str(int(timeout * 1000) if platform.system().lower() == 'windows' else int(timeout)), ip]

        try:
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )

            if output.returncode == 0:
                # Extraire le temps de réponse
                output_text = output.stdout.decode()
                time_match = re.search(r'time[=<](\d+\.?\d*)\s*ms', output_text, re.IGNORECASE)
                response_time = float(time_match.group(1)) if time_match else 0

                # Extraire le TTL
                ttl_match = re.search(r'ttl[=](\d+)', output_text, re.IGNORECASE)
                ttl = int(ttl_match.group(1)) if ttl_match else None

                return {
                    'status': 'online',
                    'response_time': response_time,
                    'ttl': ttl
                }
            else:
                return {'status': 'offline', 'response_time': None, 'ttl': None}

        except (subprocess.TimeoutExpired, Exception) as e:
            return {'status': 'offline', 'response_time': None, 'ttl': None}

    def ping_host_scapy(self, ip: str, timeout: float = PING_TIMEOUT) -> Dict:
        """
        Ping une adresse IP avec Scapy (nécessite root)

        Args:
            ip: Adresse IP à pinger
            timeout: Timeout en secondes

        Returns:
            Dictionnaire avec les résultats du ping
        """
        if not self.has_root:
            return self.ping_host(ip, timeout)

        try:
            pkt = IP(dst=ip)/ICMP()
            reply = sr1(pkt, timeout=timeout, verbose=0)

            if reply:
                return {
                    'status': 'online',
                    'response_time': reply.time * 1000,  # Convertir en ms
                    'ttl': reply.ttl
                }
            else:
                return {'status': 'offline', 'response_time': None, 'ttl': None}

        except Exception as e:
            logger.debug(f"Erreur ping Scapy pour {ip}: {e}")
            return self.ping_host(ip, timeout)

    def scan_port(self, ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
        """
        Scanne un port TCP

        Args:
            ip: Adresse IP
            port: Port à scanner
            timeout: Timeout en secondes

        Returns:
            True si le port est ouvert, False sinon
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_port_scapy(self, ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Dict:
        """
        Scanne un port avec Scapy (SYN scan, nécessite root)

        Args:
            ip: Adresse IP
            port: Port à scanner
            timeout: Timeout en secondes

        Returns:
            Dictionnaire avec les informations du port
        """
        if not self.has_root:
            is_open = self.scan_port(ip, port, timeout)
            return {
                'port': port,
                'status': 'open' if is_open else 'closed',
                'service': get_service_name(port) if is_open else None
            }

        try:
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=timeout, verbose=0)

            if reply and reply.haslayer(TCP):
                if reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Envoyer RST pour fermer la connexion
                    rst_pkt = IP(dst=ip)/TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=timeout, verbose=0)

                    return {
                        'port': port,
                        'status': 'open',
                        'service': get_service_name(port)
                    }
                elif reply.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return {
                        'port': port,
                        'status': 'closed',
                        'service': None
                    }

            return {
                'port': port,
                'status': 'filtered',
                'service': None
            }

        except Exception as e:
            logger.debug(f"Erreur scan port Scapy {ip}:{port}: {e}")
            is_open = self.scan_port(ip, port, timeout)
            return {
                'port': port,
                'status': 'open' if is_open else 'closed',
                'service': get_service_name(port) if is_open else None
            }

    def scan_ports(self, ip: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT) -> List[Dict]:
        """
        Scanne plusieurs ports

        Args:
            ip: Adresse IP
            ports: Liste des ports à scanner
            timeout: Timeout en secondes

        Returns:
            Liste des ports ouverts avec leurs informations
        """
        open_ports = []

        with ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
            if self.has_root:
                futures = {executor.submit(self.scan_port_scapy, ip, port, timeout): port for port in ports}
            else:
                futures = {executor.submit(self.scan_port, ip, port, timeout): port for port in ports}

            for future in as_completed(futures):
                port = futures[future]
                try:
                    if self.has_root:
                        result = future.result()
                        if result['status'] == 'open':
                            open_ports.append(result)
                    else:
                        is_open = future.result()
                        if is_open:
                            open_ports.append({
                                'port': port,
                                'status': 'open',
                                'service': get_service_name(port)
                            })
                except Exception as e:
                    logger.debug(f"Erreur scan port {ip}:{port}: {e}")

        return sorted(open_ports, key=lambda x: x['port'])

    def get_mac_address(self, ip: str, timeout: float = 2.0) -> str:
        """
        Récupère l'adresse MAC d'une IP (nécessite root pour ARP)

        Args:
            ip: Adresse IP
            timeout: Timeout en secondes

        Returns:
            Adresse MAC ou "N/A"
        """
        if not self.has_root:
            # Méthode alternative via /proc/net/arp (Linux)
            try:
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00':
                                return mac.upper()
            except Exception:
                pass
            return "N/A"

        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=timeout, verbose=0)[0]

            if result:
                return result[0][1].hwsrc.upper()
            else:
                return "N/A"

        except Exception as e:
            logger.debug(f"Erreur récupération MAC pour {ip}: {e}")
            return "N/A"

    def _get_local_mac_address(self) -> str:
        """
        Récupère l'adresse MAC de l'interface réseau locale

        Returns:
            Adresse MAC de l'interface principale ou "N/A"
        """
        try:
            import netifaces
            from utils import get_local_ip

            local_ip = get_local_ip()

            # Parcourir toutes les interfaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)

                # Vérifier si cette interface a l'IP locale
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if addr_info.get('addr') == local_ip:
                            # Récupérer la MAC de cette interface
                            if netifaces.AF_LINK in addrs:
                                mac = addrs[netifaces.AF_LINK][0].get('addr', 'N/A')
                                return mac.upper() if mac != 'N/A' else 'N/A'

            # Fallback: prendre la première interface non-loopback avec une MAC
            for iface in netifaces.interfaces():
                if iface != 'lo':
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_LINK in addrs:
                        mac = addrs[netifaces.AF_LINK][0].get('addr')
                        if mac and mac != '00:00:00:00:00:00':
                            return mac.upper()

        except Exception as e:
            logger.debug(f"Erreur récupération MAC locale: {e}")

        return "N/A"

    def detect_os(self, ttl: Optional[int]) -> str:
        """
        Détecte le système d'exploitation basé sur le TTL

        Args:
            ttl: Time To Live

        Returns:
            Nom du système d'exploitation détecté
        """
        if ttl is None:
            return "Unknown"

        # Trouver le TTL le plus proche
        for sig_ttl, os_name in OS_TTL_SIGNATURES.items():
            if abs(ttl - sig_ttl) <= 10:
                return os_name

        return "Unknown"

    def get_service_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """
        Tente de récupérer la bannière d'un service

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

            # Envoyer une requête HTTP basique pour les ports web
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner[:100] if banner else None

        except Exception:
            return None

    def is_local_host(self, ip: str) -> bool:
        """
        Vérifie si une IP est l'hôte local

        Args:
            ip: Adresse IP à vérifier

        Returns:
            True si c'est l'hôte local, False sinon
        """
        from utils import get_local_ip
        local_ip = get_local_ip()
        return ip == local_ip or ip == '127.0.0.1' or ip == 'localhost'

    def scan_host(self, ip: str, scan_config: Dict) -> Optional[Dict]:
        """
        Scanne un hôte complet selon la configuration

        Args:
            ip: Adresse IP à scanner
            scan_config: Configuration du scan

        Returns:
            Dictionnaire avec toutes les informations de l'hôte
        """
        if not self.is_running:
            return None

        result = {
            'ip': ip,
            'status': 'offline',
            'hostname': ip,
            'mac': 'N/A',
            'manufacturer': 'N/A',
            'os': 'Unknown',
            'response_time': None,
            'open_ports': [],
            'ports_summary': ''
        }

        # Détecter si c'est l'hôte local
        is_localhost = self.is_local_host(ip)

        # Si le ping est désactivé (scan forcé), on considère l'hôte comme online
        if not scan_config.get('ping', True):
            result['status'] = 'online'
            result['response_time'] = 0.0

        # Ping
        if scan_config.get('ping', True):
            if self.has_root and scan_config.get('use_scapy', True):
                ping_result = self.ping_host_scapy(ip, scan_config.get('timeout', PING_TIMEOUT))
            else:
                ping_result = self.ping_host(ip, scan_config.get('timeout', PING_TIMEOUT))

            # Pour l'hôte local, on force le status à online même si le ping échoue
            if ping_result['status'] == 'offline' and not is_localhost:
                return None  # Host offline, pas besoin de continuer

            if ping_result['status'] == 'online':
                result['status'] = 'online'
                result['response_time'] = ping_result['response_time']

                # Détection OS basée sur TTL
                if scan_config.get('os_detection', False) and ping_result['ttl']:
                    result['os'] = self.detect_os(ping_result['ttl'])
            elif is_localhost:
                # Pour l'hôte local, on le marque online même si le ping échoue
                result['status'] = 'online'
                result['response_time'] = 0.0
                # Détecter l'OS pour l'hôte local
                import platform
                result['os'] = f"{platform.system()} {platform.release()}"

        # Hostname
        try:
            if is_localhost:
                # Pour l'hôte local, utiliser socket.gethostname()
                import socket
                result['hostname'] = socket.gethostname()
            else:
                result['hostname'] = get_hostname(ip, timeout=1.0)
        except Exception:
            pass

        # MAC Address
        if scan_config.get('mac_address', True):
            if is_localhost:
                # Pour l'hôte local, récupérer la MAC de l'interface principale
                result['mac'] = self._get_local_mac_address()
            else:
                result['mac'] = self.get_mac_address(ip, timeout=1.0)  # Réduit de 2s à 1s

        # Détection avancée du type d'appareil via l'adresse MAC
        # La détection MAC est TOUJOURS plus précise que le TTL
        if result['mac'] and result['mac'] != 'N/A':
            vendor, device_type = get_vendor_from_mac(result['mac'])
            if vendor:
                result['manufacturer'] = vendor
            if device_type and device_type != 'Unknown':
                # Remplacer l'OS détecté par TTL avec la détection MAC (plus précise)
                result['os'] = device_type
                logger.debug(f"Appareil {ip} détecté via MAC: {device_type} ({vendor})")

        # Port scanning
        if scan_config.get('ports', False):
            port_list = scan_config.get('port_list', COMMON_PORTS)
            if port_list:
                open_ports = self.scan_ports(ip, port_list, scan_config.get('timeout', DEFAULT_TIMEOUT))
                result['open_ports'] = open_ports

                # Collecter les bannières pour TOUS les ports ouverts (pour détection OS avancée)
                banners_collected = {}

                if open_ports:
                    # Prioriser les ports importants pour la détection d'OS
                    priority_ports = [22, 80, 443, 21, 445, 8080]
                    ports_to_check = [p['port'] for p in open_ports]

                    # Trier par priorité
                    ports_to_check.sort(key=lambda x: priority_ports.index(x) if x in priority_ports else 999)

                    # Limiter à 3 ports pour ne pas ralentir (réduit de 5 à 3)
                    for port in ports_to_check[:3]:
                        banner = grab_banner(ip, port, timeout=1)  # Réduit de 2s à 1s
                        if banner:
                            banners_collected[port] = banner
                            # Ajouter la bannière au port_info si demandé
                            if scan_config.get('service_detection', False):
                                for port_info in open_ports:
                                    if port_info['port'] == port:
                                        port_info['banner'] = banner[:100]  # Limiter la taille

                # Détection OS avancée via bannières
                if banners_collected:
                    detected_os_banner = detect_os_from_banners(banners_collected)
                    if detected_os_banner:
                        # La détection via bannière est la plus précise, on la privilégie
                        result['os'] = detected_os_banner
                        logger.info(f"{ip}: OS détecté via bannières → {detected_os_banner}")

                # Summary
                if open_ports:
                    result['ports_summary'] = ', '.join([f"{p['port']}/{p['service']}" for p in open_ports[:5]])
                    if len(open_ports) > 5:
                        result['ports_summary'] += f" (+{len(open_ports) - 5} more)"

        return result

    def scan_network(self, network: str, scan_config: Dict) -> List[Dict]:
        """
        Scanne un réseau entier

        Args:
            network: Plage réseau CIDR (ex: 192.168.1.0/24)
            scan_config: Configuration du scan

        Returns:
            Liste des hôtes détectés
        """
        if not validate_network(network):
            logger.error(f"Plage réseau invalide: {network}")
            return []

        self.is_running = True
        self.results = []

        # Générer la liste des IPs
        ip_list = cidr_to_ip_list(network)
        total_ips = len(ip_list)

        self._update_progress(f"Scan de {total_ips} adresses IP...", 0)

        # Scanner avec ThreadPoolExecutor
        max_workers = min(MAX_THREADS, total_ips)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_host, ip, scan_config): ip for ip in ip_list}

            completed = 0
            for future in as_completed(futures):
                if not self.is_running:
                    # Annuler les tâches restantes
                    for f in futures:
                        f.cancel()
                    break

                ip = futures[future]
                try:
                    result = future.result()
                    if result and result['status'] == 'online':
                        self.results.append(result)
                        self._update_progress(
                            f"Trouvé: {ip} - {result.get('hostname', 'N/A')}",
                            int((completed / total_ips) * 100)
                        )
                except Exception as e:
                    logger.debug(f"Erreur scan {ip}: {e}")

                completed += 1
                if completed % 10 == 0:
                    self._update_progress(
                        f"Scanné {completed}/{total_ips} adresses...",
                        int((completed / total_ips) * 100)
                    )

        self.is_running = False

        if self.results:
            self._update_progress(f"Scan terminé: {len(self.results)} hôte(s) trouvé(s)", 100)
        else:
            self._update_progress("Scan terminé: Aucun hôte trouvé", 100)

        return self.results

    def stop_scan(self):
        """
        Arrête le scan en cours
        """
        self.is_running = False
        logger.info("Arrêt du scan demandé")

    def get_quick_scan_config(self) -> Dict:
        """
        Configuration pour un scan rapide

        Returns:
            Configuration de scan rapide
        """
        return {
            'ping': True,
            'ports': False,
            'mac_address': True,
            'os_detection': False,
            'service_detection': False,
            'timeout': PING_TIMEOUT,
            'use_scapy': self.has_root
        }

    def get_normal_scan_config(self) -> Dict:
        """
        Configuration pour un scan normal

        Returns:
            Configuration de scan normal
        """
        return {
            'ping': True,
            'ports': True,
            'port_list': COMMON_PORTS,
            'mac_address': True,
            'os_detection': False,
            'service_detection': False,
            'timeout': DEFAULT_TIMEOUT,
            'use_scapy': self.has_root
        }

    def get_deep_scan_config(self) -> Dict:
        """
        Configuration pour un scan approfondi

        Returns:
            Configuration de scan approfondi
        """
        return {
            'ping': True,
            'ports': True,
            'port_list': EXTENDED_PORTS,
            'mac_address': True,
            'os_detection': True,
            'service_detection': True,
            'timeout': DEFAULT_TIMEOUT * 2,
            'use_scapy': self.has_root
        }
