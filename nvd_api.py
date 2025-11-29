"""
Module d'interrogation de l'API NVD (National Vulnerability Database)
API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
import logging
import time
import re
from typing import List, Dict, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)

# Configuration de l'API NVD
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = None  # Optionnel: Définir une clé API pour augmenter le rate limit
REQUEST_DELAY = 6  # Délai entre requêtes en secondes (sans clé API: 5 req/30s)


def set_api_key(api_key: str):
    """
    Configure la clé API NVD (optionnel)

    Args:
        api_key: Clé API NVD
    """
    global NVD_API_KEY, REQUEST_DELAY
    NVD_API_KEY = api_key
    REQUEST_DELAY = 0.6  # Avec clé API: 50 req/30s


def search_vulnerabilities_by_keyword(keyword: str, max_results: int = 20) -> List[Dict]:
    """
    Recherche des vulnérabilités par mot-clé

    Args:
        keyword: Mot-clé de recherche (ex: "OpenSSH 7.4")
        max_results: Nombre maximum de résultats

    Returns:
        Liste de vulnérabilités
    """
    vulnerabilities = []

    try:
        # Construire l'URL de recherche
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(max_results, 100)  # Max 100 par page
        }

        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY

        logger.info(f"Recherche NVD: {keyword}")

        # Appel API
        response = requests.get(
            NVD_API_BASE_URL,
            params=params,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()

            if 'vulnerabilities' in data:
                for item in data['vulnerabilities'][:max_results]:
                    cve_data = item.get('cve', {})
                    vuln = parse_cve_data(cve_data)
                    if vuln:
                        vulnerabilities.append(vuln)

            logger.info(f"Trouvé {len(vulnerabilities)} vulnérabilité(s) pour '{keyword}'")

        elif response.status_code == 403:
            logger.error("API NVD: Rate limit dépassé")
        else:
            logger.error(f"Erreur API NVD: {response.status_code}")

        # Respecter le rate limit
        time.sleep(REQUEST_DELAY)

    except requests.RequestException as e:
        logger.error(f"Erreur connexion API NVD: {e}")
    except Exception as e:
        logger.error(f"Erreur recherche NVD: {e}")

    return vulnerabilities


def search_vulnerabilities_by_cpe(cpe: str, max_results: int = 20) -> List[Dict]:
    """
    Recherche des vulnérabilités par CPE (Common Platform Enumeration)

    Args:
        cpe: CPE string (ex: "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*")
        max_results: Nombre maximum de résultats

    Returns:
        Liste de vulnérabilités
    """
    vulnerabilities = []

    try:
        params = {
            'cpeName': cpe,
            'resultsPerPage': min(max_results, 100)
        }

        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY

        logger.info(f"Recherche NVD par CPE: {cpe}")

        response = requests.get(
            NVD_API_BASE_URL,
            params=params,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()

            if 'vulnerabilities' in data:
                for item in data['vulnerabilities'][:max_results]:
                    cve_data = item.get('cve', {})
                    vuln = parse_cve_data(cve_data)
                    if vuln:
                        vulnerabilities.append(vuln)

            logger.info(f"Trouvé {len(vulnerabilities)} vulnérabilité(s) pour CPE '{cpe}'")

        time.sleep(REQUEST_DELAY)

    except Exception as e:
        logger.error(f"Erreur recherche CPE: {e}")

    return vulnerabilities


def parse_cve_data(cve_data: Dict) -> Optional[Dict]:
    """
    Parse les données d'une CVE depuis l'API NVD

    Args:
        cve_data: Données JSON de la CVE

    Returns:
        Dictionnaire de vulnérabilité formaté
    """
    try:
        cve_id = cve_data.get('id', 'UNKNOWN')

        # Description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # Score CVSS
        cvss_score = None
        severity = 'INCONNU'

        metrics = cve_data.get('metrics', {})

        # Essayer CVSS v3.1 en priorité
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_score = cvss_v3.get('baseScore')
            severity = cvss_v3.get('baseSeverity', 'INCONNU')

        # Sinon CVSS v3.0
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_score = cvss_v3.get('baseScore')
            severity = cvss_v3.get('baseSeverity', 'INCONNU')

        # Sinon CVSS v2
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
            cvss_score = cvss_v2.get('baseScore')
            # Convertir severity CVSS v2
            if cvss_score:
                if cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'

        # Convertir severity en français
        severity_fr = {
            'CRITICAL': 'CRITIQUE',
            'HIGH': 'ÉLEVÉ',
            'MEDIUM': 'MOYEN',
            'LOW': 'FAIBLE',
            'INCONNU': 'INCONNU'
        }.get(severity, severity)

        # Dates
        published = cve_data.get('published', '')
        modified = cve_data.get('lastModified', '')

        # Références
        references = []
        refs = cve_data.get('references', [])
        for ref in refs[:5]:  # Limiter à 5 références
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', '')
            })

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity_fr,
            'description': description[:500],  # Limiter la taille
            'published': published,
            'modified': modified,
            'references': references,
            'source': 'NVD API'
        }

    except Exception as e:
        logger.error(f"Erreur parsing CVE: {e}")
        return None


def search_vulnerabilities_for_service(service_name: str, version: str, max_results: int = 10) -> List[Dict]:
    """
    Recherche des vulnérabilités pour un service et sa version

    Args:
        service_name: Nom du service (ex: "OpenSSH", "Apache", "nginx")
        version: Version (ex: "7.4", "2.4.29")
        max_results: Nombre maximum de résultats

    Returns:
        Liste de vulnérabilités
    """
    # Normaliser le nom du service
    service_map = {
        'ssh': 'OpenSSH',
        'openssh': 'OpenSSH',
        'http': 'Apache',
        'apache': 'Apache httpd',
        'nginx': 'nginx',
        'ftp': 'ProFTPD',
        'mysql': 'MySQL',
        'postgresql': 'PostgreSQL',
        'smb': 'Samba',
        'samba': 'Samba',
    }

    service_normalized = service_map.get(service_name.lower(), service_name)

    # Construire la requête de recherche
    keyword = f"{service_normalized} {version}"

    return search_vulnerabilities_by_keyword(keyword, max_results)


def extract_service_info_from_banner(banner: str, port: int) -> Optional[Dict]:
    """
    Extrait le nom et la version d'un service depuis une bannière

    Args:
        banner: Bannière du service
        port: Port du service

    Returns:
        Dictionnaire {service, version} ou None
    """
    if not banner:
        return None

    # Patterns pour différents services
    patterns = {
        'ssh': r'SSH-[\d.]+[-_]?([A-Za-z]+)[_\-]?([\d.]+)',  # SSH-2.0-OpenSSH_7.4
        'http_server': r'Server:\s*([A-Za-z/\-]+)/([\d.]+)',  # Server: Apache/2.4.29
        'ftp': r'(\w+)\s+([\d.]+)\s+Server',  # ProFTPD 1.3.6 Server
        'mysql': r'(MySQL)\s+([\d.]+)',
        'nginx': r'(nginx)/([\d.]+)',
    }

    for service_type, pattern in patterns.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            service = match.group(1)
            version = match.group(2)

            # Nettoyer la version (enlever les suffixes)
            version = re.sub(r'[a-z].*$', '', version, flags=re.IGNORECASE)

            return {
                'service': service,
                'version': version
            }

    return None


def scan_vulnerabilities_nvd(ip: str, open_ports: List[Dict], max_per_service: int = 5) -> Dict:
    """
    Scanne les vulnérabilités d'un hôte via l'API NVD

    Args:
        ip: Adresse IP
        open_ports: Liste des ports ouverts avec bannières
        max_per_service: Nombre max de vulnérabilités par service

    Returns:
        Dictionnaire avec les vulnérabilités trouvées
    """
    result = {
        'ip': ip,
        'vulnerabilities': [],
        'error': None
    }

    try:
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', 'unknown')
            banner = port_info.get('banner', '')

            # Essayer d'extraire la version depuis la bannière
            service_info = extract_service_info_from_banner(banner, port)

            if service_info:
                service_name = service_info['service']
                version = service_info['version']

                logger.info(f"Recherche NVD pour {service_name} {version} sur port {port}")

                # Rechercher les vulnérabilités
                vulns = search_vulnerabilities_for_service(service_name, version, max_per_service)

                # Ajouter les infos de port
                for vuln in vulns:
                    vuln['port'] = port
                    vuln['service'] = service
                    vuln['version'] = version
                    result['vulnerabilities'].append(vuln)
            else:
                logger.debug(f"Impossible d'extraire la version pour le port {port}")

        logger.info(f"Scan NVD terminé pour {ip}: {len(result['vulnerabilities'])} vulnérabilité(s)")

    except Exception as e:
        logger.error(f"Erreur scan NVD pour {ip}: {e}")
        result['error'] = str(e)

    return result


def get_nvd_api_info():
    """
    Retourne les informations sur l'API NVD

    Returns:
        Dictionnaire d'informations
    """
    return {
        'api_url': NVD_API_BASE_URL,
        'has_api_key': NVD_API_KEY is not None,
        'rate_limit': '50 req/30s' if NVD_API_KEY else '5 req/30s',
        'request_delay': REQUEST_DELAY,
        'documentation': 'https://nvd.nist.gov/developers/vulnerabilities',
        'api_key_request': 'https://nvd.nist.gov/developers/request-an-api-key'
    }
