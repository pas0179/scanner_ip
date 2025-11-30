"""
Module de scan WiFi et capture de handshakes WPA/WPA2
IMPORTANT: Utilisation autorisée uniquement pour tests sur vos propres réseaux
"""

import subprocess
import re
import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import os
import shutil

# Scapy imports pour la capture WiFi
try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq,
        Dot11AssoResp, Dot11ProbeReq, Dot11ProbeResp, EAPOL,
        RadioTap, sniff, wrpcap
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class WiFiNetwork:
    """Représente un réseau WiFi détecté"""
    ssid: str
    bssid: str  # MAC du point d'accès
    channel: int
    encryption: str  # WPA, WPA2, WPA3, WEP, Open
    signal_strength: int  # en dBm
    clients: List[str]  # Liste des MACs clients connectés
    handshakes_captured: int = 0


class WiFiScanner:
    """
    Scanner WiFi pour détecter les réseaux et capturer les handshakes
    NÉCESSITE ROOT/SUDO pour fonctionner
    """

    def __init__(self, interface: str = None, callback: Optional[Callable] = None):
        """
        Initialise le scanner WiFi

        Args:
            interface: Interface WiFi à utiliser (ex: wlan0, wlan0mon)
            callback: Fonction de callback pour les mises à jour
        """
        self.interface = interface
        self.callback = callback
        self.is_running = False
        self.networks = {}  # BSSID -> WiFiNetwork
        self.handshakes = []  # Liste des handshakes capturés

        # Vérifier les droits root
        if os.geteuid() != 0:
            logger.warning("⚠️ WiFi scanner nécessite les droits root/sudo")

        # Vérifier scapy
        if not SCAPY_AVAILABLE:
            logger.error("Scapy n'est pas installé ou incomplet")

    def _update_progress(self, message: str, progress: int = 0):
        """Met à jour la progression via callback"""
        if self.callback:
            self.callback(message, progress)
        logger.info(message)

    def check_requirements(self) -> Dict[str, bool]:
        """
        Vérifie les dépendances nécessaires

        Returns:
            Dictionnaire avec l'état des dépendances
        """
        requirements = {
            'root_access': os.geteuid() == 0,
            'scapy': SCAPY_AVAILABLE,
            'aircrack_ng': shutil.which('aircrack-ng') is not None,
            'airmon_ng': shutil.which('airmon-ng') is not None,
            'airodump_ng': shutil.which('airodump-ng') is not None,
        }
        return requirements

    def get_wifi_interfaces(self) -> List[str]:
        """
        Liste les interfaces WiFi disponibles

        Returns:
            Liste des noms d'interfaces WiFi
        """
        interfaces = []

        try:
            # Méthode 1: via iwconfig
            if shutil.which('iwconfig'):
                result = subprocess.run(
                    ['iwconfig'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line or 'ESSID' in line:
                        interface = line.split()[0]
                        if interface and interface not in interfaces:
                            interfaces.append(interface)

            # Méthode 2: via /sys/class/net
            if not interfaces and os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    wireless_path = f'/sys/class/net/{iface}/wireless'
                    if os.path.exists(wireless_path):
                        interfaces.append(iface)

        except Exception as e:
            logger.error(f"Erreur lors de la détection des interfaces WiFi: {e}")

        return interfaces

    def enable_monitor_mode(self, interface: str = None) -> Optional[str]:
        """
        Active le mode moniteur sur l'interface WiFi

        Args:
            interface: Interface à mettre en mode moniteur

        Returns:
            Nom de l'interface en mode moniteur (ex: wlan0mon) ou None si échec
        """
        if not interface:
            interface = self.interface

        if not interface:
            logger.error("Aucune interface WiFi spécifiée")
            return None

        try:
            # Vérifier si airmon-ng est disponible
            if shutil.which('airmon-ng'):
                self._update_progress(f"Activation du mode moniteur sur {interface}...")

                # Arrêter les processus qui pourraient interférer
                subprocess.run(['airmon-ng', 'check', 'kill'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Activer le mode moniteur
                result = subprocess.run(
                    ['airmon-ng', 'start', interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Extraire le nom de l'interface en mode moniteur
                for line in result.stdout.split('\n'):
                    if 'monitor mode enabled' in line.lower() or 'enabled on' in line.lower():
                        # Généralement wlan0 -> wlan0mon
                        mon_interface = f"{interface}mon"
                        if os.path.exists(f'/sys/class/net/{mon_interface}'):
                            self._update_progress(f"✓ Mode moniteur activé: {mon_interface}")
                            return mon_interface

                # Si pas trouvé, essayer avec le nom standard
                mon_interface = f"{interface}mon"
                if os.path.exists(f'/sys/class/net/{mon_interface}'):
                    return mon_interface

            else:
                # Méthode manuelle avec iwconfig
                self._update_progress("airmon-ng non disponible, méthode manuelle...")

                # Désactiver l'interface
                subprocess.run(['ip', 'link', 'set', interface, 'down'])

                # Activer le mode moniteur
                subprocess.run(['iwconfig', interface, 'mode', 'monitor'])

                # Réactiver l'interface
                subprocess.run(['ip', 'link', 'set', interface, 'up'])

                self._update_progress(f"✓ Mode moniteur activé (méthode manuelle): {interface}")
                return interface

        except Exception as e:
            logger.error(f"Erreur lors de l'activation du mode moniteur: {e}")
            return None

        return None

    def disable_monitor_mode(self, interface: str = None) -> bool:
        """
        Désactive le mode moniteur

        Args:
            interface: Interface en mode moniteur

        Returns:
            True si succès, False sinon
        """
        if not interface:
            interface = self.interface

        if not interface:
            return False

        try:
            if shutil.which('airmon-ng'):
                subprocess.run(['airmon-ng', 'stop', interface],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self._update_progress(f"✓ Mode moniteur désactivé: {interface}")
                return True
            else:
                # Méthode manuelle
                subprocess.run(['ip', 'link', 'set', interface, 'down'])
                subprocess.run(['iwconfig', interface, 'mode', 'managed'])
                subprocess.run(['ip', 'link', 'set', interface, 'up'])
                return True

        except Exception as e:
            logger.error(f"Erreur lors de la désactivation du mode moniteur: {e}")
            return False

    def scan_networks_airodump(self, interface: str, duration: int = 30) -> List[WiFiNetwork]:
        """
        Scanne les réseaux WiFi avec airodump-ng

        Args:
            interface: Interface en mode moniteur
            duration: Durée du scan en secondes

        Returns:
            Liste des réseaux détectés
        """
        if not shutil.which('airodump-ng'):
            logger.error("airodump-ng n'est pas installé")
            return []

        output_file = f"/tmp/wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        try:
            self._update_progress(f"Scan des réseaux WiFi pendant {duration}s...")

            # Lancer airodump-ng
            process = subprocess.Popen(
                ['airodump-ng', '--write', output_file, '--output-format', 'csv', interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Attendre la durée spécifiée
            import time
            time.sleep(duration)

            # Arrêter le processus
            process.terminate()
            process.wait(timeout=5)

            # Parser le fichier CSV
            csv_file = f"{output_file}-01.csv"
            if os.path.exists(csv_file):
                networks = self._parse_airodump_csv(csv_file)
                self._update_progress(f"✓ {len(networks)} réseaux détectés")
                return networks

        except Exception as e:
            logger.error(f"Erreur lors du scan avec airodump-ng: {e}")

        finally:
            # Nettoyer les fichiers temporaires
            for ext in ['.csv', '.cap', '.kismet.csv', '.kismet.netxml', '.log.csv']:
                temp_file = f"{output_file}-01{ext}"
                if os.path.exists(temp_file):
                    os.remove(temp_file)

        return []

    def _parse_airodump_csv(self, csv_file: str) -> List[WiFiNetwork]:
        """Parse le fichier CSV de airodump-ng"""
        networks = []

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Séparer les sections APs et Stations
            sections = content.split('\n\n')
            if len(sections) < 1:
                return networks

            # Parser les Access Points
            ap_lines = sections[0].split('\n')[2:]  # Skip header

            for line in ap_lines:
                if not line.strip():
                    continue

                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue

                bssid = parts[0]
                channel = parts[3]
                encryption = parts[5]
                power = parts[8]
                ssid = parts[13]

                if bssid and bssid != 'BSSID':
                    try:
                        network = WiFiNetwork(
                            ssid=ssid if ssid else '<Hidden>',
                            bssid=bssid,
                            channel=int(channel) if channel.isdigit() else 0,
                            encryption=encryption,
                            signal_strength=int(power) if power.lstrip('-').isdigit() else -100,
                            clients=[]
                        )
                        networks.append(network)
                        self.networks[bssid] = network
                    except Exception as e:
                        logger.debug(f"Erreur parsing ligne AP: {e}")

        except Exception as e:
            logger.error(f"Erreur parsing CSV airodump: {e}")

        return networks

    def capture_handshake_scapy(self, bssid: str, channel: int, interface: str,
                                duration: int = 60, output_file: str = None) -> bool:
        """
        Capture un handshake WPA/WPA2 avec Scapy

        Args:
            bssid: BSSID du réseau cible
            channel: Canal WiFi
            interface: Interface en mode moniteur
            duration: Durée de capture en secondes
            output_file: Fichier de sortie .pcap (optionnel)

        Returns:
            True si handshake capturé, False sinon
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy n'est pas disponible")
            return False

        self._update_progress(f"Capture du handshake pour {bssid} sur canal {channel}...")

        # Changer de canal
        try:
            subprocess.run(['iwconfig', interface, 'channel', str(channel)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logger.warning(f"Erreur changement de canal: {e}")

        # Variables pour la capture
        handshake_packets = []
        eapol_count = 0

        def packet_handler(pkt):
            nonlocal eapol_count

            # Vérifier si c'est un paquet EAPOL (partie du handshake)
            if pkt.haslayer(EAPOL):
                # Vérifier si c'est le bon BSSID
                if pkt.haslayer(Dot11) and pkt.addr2 == bssid or pkt.addr1 == bssid:
                    handshake_packets.append(pkt)
                    eapol_count += 1
                    self._update_progress(f"Paquet EAPOL {eapol_count}/4 capturé")

                    # Un handshake complet = 4 paquets EAPOL
                    if eapol_count >= 4:
                        return True  # Stopper le sniff

            return False

        try:
            # Capturer les paquets
            packets = sniff(
                iface=interface,
                prn=packet_handler,
                timeout=duration,
                store=True
            )

            # Sauvegarder si demandé
            if output_file and handshake_packets:
                wrpcap(output_file, handshake_packets)
                self._update_progress(f"✓ Handshake sauvegardé: {output_file}")

            # Vérifier si on a capturé un handshake complet
            if eapol_count >= 4:
                self._update_progress(f"✓ Handshake complet capturé pour {bssid}")
                return True
            elif eapol_count > 0:
                self._update_progress(f"⚠️ Handshake partiel ({eapol_count}/4 paquets)")
                return False
            else:
                self._update_progress(f"✗ Aucun paquet EAPOL capturé")
                return False

        except Exception as e:
            logger.error(f"Erreur lors de la capture: {e}")
            return False

    def extract_hash_from_pcap(self, pcap_file: str) -> Optional[str]:
        """
        Extrait le hash WPA/WPA2 d'un fichier .pcap avec aircrack-ng

        Args:
            pcap_file: Fichier .pcap contenant le handshake

        Returns:
            Hash au format hashcat ou None
        """
        if not shutil.which('aircrack-ng'):
            logger.error("aircrack-ng n'est pas installé")
            return None

        try:
            # Vérifier si le handshake est valide
            result = subprocess.run(
                ['aircrack-ng', pcap_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )

            # Si handshake trouvé, convertir au format hashcat
            if 'handshake' in result.stdout.lower():
                # Utiliser hcxpcapngtool si disponible (meilleur pour hashcat)
                if shutil.which('hcxpcapngtool'):
                    hash_file = pcap_file.replace('.pcap', '.hc22000')

                    subprocess.run(
                        ['hcxpcapngtool', '-o', hash_file, pcap_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )

                    if os.path.exists(hash_file):
                        with open(hash_file, 'r') as f:
                            hash_content = f.read().strip()
                        self._update_progress(f"✓ Hash extrait: {hash_file}")
                        return hash_content

                # Alternative: utiliser aircrack-ng pour PMKID
                self._update_progress("✓ Handshake valide trouvé (utilisez aircrack-ng ou hashcat)")
                return pcap_file  # Retourner le chemin du pcap

        except Exception as e:
            logger.error(f"Erreur extraction hash: {e}")

        return None

    def get_installation_instructions(self) -> str:
        """
        Instructions pour installer les outils nécessaires

        Returns:
            Instructions formatées
        """
        return """
INSTALLATION DES OUTILS WIFI
=============================

1. Aircrack-ng Suite (REQUIS):
   sudo apt-get update
   sudo apt-get install aircrack-ng

2. hcxtools (pour conversion hashcat - OPTIONNEL):
   sudo apt-get install hcxtools

3. Scapy (déjà installé dans votre projet)

4. Vérifier l'installation:
   airmon-ng
   airodump-ng --help
   hcxpcapngtool --version

UTILISATION:
============

1. Lister les interfaces WiFi:
   scanner = WiFiScanner()
   interfaces = scanner.get_wifi_interfaces()

2. Activer le mode moniteur:
   mon_interface = scanner.enable_monitor_mode('wlan0')

3. Scanner les réseaux:
   networks = scanner.scan_networks_airodump(mon_interface, duration=30)

4. Capturer un handshake:
   scanner.capture_handshake_scapy(
       bssid='AA:BB:CC:DD:EE:FF',
       channel=6,
       interface=mon_interface,
       output_file='/tmp/handshake.pcap'
   )

5. Extraire le hash:
   hash_value = scanner.extract_hash_from_pcap('/tmp/handshake.pcap')

IMPORTANT:
==========
- Nécessite les droits ROOT/SUDO
- Utilisation autorisée uniquement sur VOS propres réseaux
- Tests d'intrusion avec autorisation écrite uniquement
"""
