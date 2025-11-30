"""
Module pour les scans Nmap avancés avec options personnalisées
"""

import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ===== PRESETS DE SCAN NMAP =====

NMAP_SCAN_PRESETS = {
    'quick': {
        'name': 'Scan Rapide',
        'description': 'Scan rapide des ports les plus communs',
        'options': {
            'scan_type': 'syn',
            'timing': 'T4',
            'os_detection': False,
            'version_detection': False,
            'script_scan': False,
            'traceroute': False,
            'port_range': '1-1000'
        }
    },
    'standard': {
        'name': 'Scan Standard',
        'description': 'Scan équilibré avec détection de version (comme votre exemple)',
        'options': {
            'scan_type': 'syn',
            'timing': 'T4',
            'os_detection': True,
            'version_detection': True,
            'script_scan': False,
            'traceroute': False,
            'port_range': '1-1000',
            'reason': True
        }
    },
    'comprehensive': {
        'name': 'Scan Complet',
        'description': 'Scan approfondi avec tous les ports et scripts',
        'options': {
            'scan_type': 'syn',
            'timing': 'T4',
            'os_detection': True,
            'version_detection': True,
            'version_intensity': 9,
            'script_scan': 'default,vuln',
            'traceroute': True,
            'port_range': '1-65535',
            'reason': True
        }
    },
    'stealth': {
        'name': 'Scan Furtif',
        'description': 'Scan discret et lent pour éviter la détection',
        'options': {
            'scan_type': 'syn',
            'timing': 'T2',
            'os_detection': False,
            'version_detection': False,
            'script_scan': False,
            'traceroute': False,
            'port_range': '1-1000',
            'fragment_packets': True,
            'randomize_hosts': True
        }
    },
    'aggressive': {
        'name': 'Scan Agressif',
        'description': 'Scan très rapide et complet (équivalent -A -T5)',
        'options': {
            'scan_type': 'aggressive',
            'timing': 'T5',
            'os_detection': True,
            'version_detection': True,
            'script_scan': 'default',
            'traceroute': True,
            'port_range': '1-10000'
        }
    },
    'udp_scan': {
        'name': 'Scan UDP',
        'description': 'Scan des ports UDP (nécessite root)',
        'options': {
            'scan_type': 'udp',
            'timing': 'T4',
            'os_detection': False,
            'version_detection': True,
            'script_scan': False,
            'traceroute': False,
            'port_range': '53,67,68,69,123,135,137,138,161,162,445,500,514,1434'
        }
    }
}


def get_preset_options(preset_name: str) -> Dict:
    """
    Récupère les options d'un preset de scan

    Args:
        preset_name: Nom du preset ('quick', 'standard', 'comprehensive', etc.)

    Returns:
        Dictionnaire des options Nmap
    """
    if preset_name in NMAP_SCAN_PRESETS:
        return NMAP_SCAN_PRESETS[preset_name]['options'].copy()
    else:
        logger.warning(f"Preset '{preset_name}' inconnu, utilisation du preset 'standard'")
        return NMAP_SCAN_PRESETS['standard']['options'].copy()


def list_presets() -> List[Dict]:
    """
    Liste tous les presets disponibles

    Returns:
        Liste des presets avec leur nom et description
    """
    presets = []
    for key, value in NMAP_SCAN_PRESETS.items():
        presets.append({
            'key': key,
            'name': value['name'],
            'description': value['description']
        })
    return presets


def run_nmap_advanced_scan(ip: str, ports: List[int], nmap_options: Dict, sudo_password: str = None, output_file: str = None, progress_callback=None, scan_control: dict = None) -> Dict:
    """
    Exécute un scan Nmap avancé avec options personnalisées

    Args:
        ip: Adresse IP à scanner
        ports: Liste des ports à scanner (peut être None si port_range est spécifié)
        nmap_options: Dictionnaire des options Nmap
        sudo_password: Mot de passe sudo (optionnel)
        output_file: Chemin de base pour sauvegarder les résultats (-oA)
        progress_callback: Fonction callback(port, status, service, version) pour progression
        scan_control: Dictionnaire avec flag 'running' pour contrôler le scan

    Returns:
        Dictionnaire avec les informations détaillées
    """
    result = {
        'ip': ip,
        'os_details': {},
        'traceroute': [],
        'scripts_output': {},
        'detailed_ports': [],
        'error': None,
        'output_files': []
    }

    try:
        import os

        # Déterminer si le scan nécessite les droits root
        scan_type = nmap_options.get('scan_type', 'default')
        scan_requires_root = (scan_type in ['syn', 'aggressive', 'udp', 'fin', 'null', 'xmas'] or
                              nmap_options.get('os_detection', False) or
                              nmap_options.get('traceroute', False))

        is_already_root = os.geteuid() == 0
        needs_sudo_prompt = scan_requires_root and not is_already_root

        # Construire la commande Nmap
        nmap_cmd = []

        # Gérer les privilèges
        if needs_sudo_prompt:
            if sudo_password:
                nmap_cmd.extend(['sudo', '-S'])  # -S pour lire le mot de passe depuis stdin
                logger.info("Utilisation de sudo -S pour le scan Nmap")
            else:
                logger.warning("Sudo requis mais pas de mot de passe fourni, certaines options seront limitées.")
        elif scan_requires_root and is_already_root:
            # Déjà root, on ajoute 'sudo' pour garantir l'exécution en tant que root dans le sous-processus.
            nmap_cmd.append('sudo')
            logger.info("Exécution en tant que root, 'sudo' ajouté à la commande Nmap pour garantir les privilèges.")

        nmap_cmd.append('nmap')

        # Type de scan
        if scan_type == 'syn':
            nmap_cmd.append('-sS')
        elif scan_type == 'tcp':
            nmap_cmd.append('-sT')
        elif scan_type == 'udp':
            nmap_cmd.append('-sU')
        elif scan_type == 'fin':
            nmap_cmd.append('-sF')
        elif scan_type == 'null':
            nmap_cmd.append('-sN')
        elif scan_type == 'xmas':
            nmap_cmd.append('-sX')
        elif scan_type == 'aggressive':
            nmap_cmd.append('-A')

        # Timing (T0 à T5)
        timing = nmap_options.get('timing', 'T3')
        if timing in ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']:
            nmap_cmd.append(f'-{timing}')
        else:
            nmap_cmd.append('-T3')  # Par défaut

        # Détection OS
        if nmap_options.get('os_detection', False):
            # Vérifier si nous avons les privilèges nécessaires
            has_privileges = (needs_sudo_prompt and sudo_password) or is_already_root
            if scan_requires_root and has_privileges:
                nmap_cmd.append('-O')
            elif scan_requires_root: # Si on a besoin de root mais qu'on ne l'a pas
                logger.warning("La détection d'OS (-O) nécessite les droits root. Utilisation de --osscan-guess.")
                nmap_cmd.append('--osscan-guess')

        # Détection de version
        if nmap_options.get('version_detection', False):
            nmap_cmd.extend(['-sV', '--version-intensity', '9'])

        # Scripts NSE (avec options personnalisées)
        script_option = nmap_options.get('script_scan', False)
        if script_option:
            if isinstance(script_option, str):
                # Script personnalisé (ex: "vuln", "exploit", "discovery")
                nmap_cmd.extend(['--script', script_option])
            else:
                # Par défaut
                nmap_cmd.extend(['--script', 'default'])

        # Traceroute
        if nmap_options.get('traceroute', False):
            nmap_cmd.append('--traceroute')

        # Ports (avec support pour port_range personnalisé)
        port_range = nmap_options.get('port_range', None)
        if port_range:
            # Format personnalisé (ex: "1-1000,8080,9000")
            nmap_cmd.extend(['-p', port_range])
        elif ports:
            port_list = ','.join(map(str, ports))
            nmap_cmd.extend(['-p', port_list])

        # Options supplémentaires
        if nmap_options.get('fragment_packets', False):
            nmap_cmd.append('-f')  # Fragmentation de paquets

        if nmap_options.get('randomize_hosts', False):
            nmap_cmd.append('--randomize-hosts')

        if nmap_options.get('reason', False):
            nmap_cmd.append('--reason')  # Afficher la raison de l'état du port

        # Intensity pour version scan
        version_intensity = nmap_options.get('version_intensity', None)
        if version_intensity and nmap_options.get('version_detection', False):
            nmap_cmd.extend(['--version-intensity', str(version_intensity)])

        # Sauvegarde des résultats (-oA)
        if output_file:
            nmap_cmd.extend(['-oA', output_file])
            result['output_files'] = [
                f"{output_file}.nmap",
                f"{output_file}.xml",
                f"{output_file}.gnmap"
            ]

        # Format XML pour parsing (toujours actif)
        nmap_cmd.extend(['-oX', '-'])

        # IP cible
        nmap_cmd.append(ip)

        logger.info(f"Commande Nmap avancée: {' '.join(nmap_cmd)}")

        # Ajouter --stats-every pour avoir des mises à jour de progression
        nmap_cmd.insert(-1, '--stats-every')
        nmap_cmd.insert(-1, '2s')

        # Exécuter Nmap avec Popen pour lire la sortie en temps réel
        if needs_sudo_prompt and sudo_password:
            # Avec sudo
            process = subprocess.Popen(
                nmap_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            # Envoyer le mot de passe sudo
            process.stdin.write(f"{sudo_password}\n")
            process.stdin.flush()
        else:
            # Sans sudo
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

        # Stocker le processus pour permettre l'arrêt
        if scan_control:
            scan_control['nmap_process'] = process

        # Lire la sortie en temps réel
        output_lines = []
        stderr_lines = []

        try:
            import re
            import time

            # Pattern pour détecter les ports dans la sortie
            port_pattern = re.compile(r'(\d+)/tcp\s+(\w+)\s+(\S+)')

            while True:
                # Vérifier si le scan doit s'arrêter
                if scan_control and not scan_control.get('running', True):
                    logger.info("Arrêt du scan Nmap demandé")
                    process.terminate()
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()
                    break

                # Lire une ligne de stdout
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break

                if line:
                    output_lines.append(line)

                    # Parser la ligne pour détecter les ports
                    if progress_callback and port_pattern.search(line):
                        match = port_pattern.search(line)
                        if match:
                            port_num = int(match.group(1))
                            status = match.group(2)
                            service = match.group(3)
                            progress_callback(port_num, status, service, "")

            # Lire stderr
            stderr_output = process.stderr.read()
            if stderr_output:
                stderr_lines.append(stderr_output)

            # Attendre la fin du processus
            returncode = process.wait(timeout=10)
            process_output = ''.join(output_lines)

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors du scan Nmap de {ip}")
            process.kill()
            result['error'] = "Timeout (300s)"
            return result
        except Exception as e:
            logger.error(f"Erreur lors du scan Nmap: {e}")
            try:
                process.kill()
            except:
                pass
            result['error'] = str(e)
            return result

        # Créer un objet compatible avec l'ancien code
        class ProcessResult:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        process = ProcessResult(returncode, process_output, ''.join(stderr_lines))

        if process.returncode != 0:
            error_msg = process.stderr if process.stderr else "Code de retour non-zéro"
            logger.error(f"Erreur Nmap (code {process.returncode}): {error_msg}")
            result['error'] = f"Erreur Nmap: {error_msg[:200]}"
            # Essayer quand même de parser le XML si disponible
            if process.stdout:
                try:
                    parse_nmap_advanced_xml(process.stdout, result)
                except Exception as e:
                    logger.error(f"Erreur parsing XML malgré l'erreur Nmap: {e}")
            return result

        # Parser le XML
        if process.stdout:
            parse_nmap_advanced_xml(process.stdout, result)
            logger.info(f"Parsing XML terminé. OS détails: {bool(result.get('os_details'))}, Traceroute: {len(result.get('traceroute', []))}, Ports: {len(result.get('detailed_ports', []))}")
        else:
            logger.warning("Aucune sortie XML de Nmap")

        logger.info(f"Scan Nmap avancé terminé pour {ip}")

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout lors du scan Nmap de {ip}")
        result['error'] = "Timeout (300s)"
    except Exception as e:
        logger.error(f"Erreur lors du scan Nmap de {ip}: {e}")
        result['error'] = str(e)

    return result


def parse_nmap_advanced_xml(xml_output: str, result: Dict):
    """
    Parse la sortie XML de Nmap pour extraire toutes les informations détaillées

    Args:
        xml_output: Sortie XML de Nmap
        result: Dictionnaire de résultats à remplir
    """
    try:
        root = ET.fromstring(xml_output)

        # Parcourir les hôtes
        for host in root.findall('.//host'):
            # ===== OS DETECTION =====
            os_elem = host.find('.//osmatch')
            if os_elem is not None:
                result['os_details'] = {
                    'name': os_elem.get('name', 'Unknown'),
                    'accuracy': os_elem.get('accuracy', '0'),
                    'type': '',
                    'vendor': '',
                    'family': ''
                }

                # Classes OS
                osclass = os_elem.find('.//osclass')
                if osclass is not None:
                    result['os_details']['type'] = osclass.get('type', '')
                    result['os_details']['vendor'] = osclass.get('vendor', '')
                    result['os_details']['family'] = osclass.get('osfamily', '')

            # ===== TRACEROUTE =====
            trace = host.find('.//trace')
            if trace is not None:
                hops = []
                for hop in trace.findall('.//hop'):
                    hops.append({
                        'ttl': hop.get('ttl'),
                        'ip': hop.get('ipaddr'),
                        'host': hop.get('host', ''),
                        'rtt': hop.get('rtt', '')
                    })
                result['traceroute'] = hops

            # ===== PORTS DÉTAILLÉS =====
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')

                # État du port
                state = port.find('state')
                state_info = {
                    'state': state.get('state') if state is not None else 'unknown',
                    'reason': state.get('reason') if state is not None else ''
                }

                # Service
                service = port.find('service')
                service_info = {}
                if service is not None:
                    service_info = {
                        'name': service.get('name', 'unknown'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                        'ostype': service.get('ostype', ''),
                        'method': service.get('method', ''),
                        'conf': service.get('conf', '')
                    }

                # Scripts NSE
                scripts = {}
                for script in port.findall('.//script'):
                    script_id = script.get('id')
                    script_output = script.get('output', '')
                    scripts[script_id] = script_output

                result['detailed_ports'].append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state_info,
                    'service': service_info,
                    'scripts': scripts
                })

            # ===== SCRIPTS HOST =====
            hostscript = host.find('.//hostscript')
            if hostscript is not None:
                for script in hostscript.findall('.//script'):
                    script_id = script.get('id')
                    script_output = script.get('output', '')
                    result['scripts_output'][script_id] = script_output

    except ET.ParseError as e:
        logger.error(f"Erreur parsing XML Nmap: {e}")
    except Exception as e:
        logger.error(f"Erreur inattendue lors du parsing Nmap: {e}")


def format_nmap_results_summary(nmap_result: Dict) -> str:
    """
    Formate un résumé des résultats Nmap

    Args:
        nmap_result: Résultats du scan Nmap

    Returns:
        Résumé formaté
    """
    summary = []

    # OS
    if nmap_result.get('os_details'):
        os_info = nmap_result['os_details']
        summary.append(f"OS: {os_info.get('name', 'Unknown')} ({os_info.get('accuracy', '0')}% confiance)")

    # Traceroute
    if nmap_result.get('traceroute'):
        summary.append(f"Traceroute: {len(nmap_result['traceroute'])} sauts")

    # Ports détaillés
    if nmap_result.get('detailed_ports'):
        summary.append(f"Ports analysés: {len(nmap_result['detailed_ports'])}")

    # Scripts
    if nmap_result.get('scripts_output'):
        summary.append(f"Scripts exécutés: {len(nmap_result['scripts_output'])}")

    return " | ".join(summary) if summary else "Aucune information supplémentaire"
