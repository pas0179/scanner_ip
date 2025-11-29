#!/usr/bin/env python3
"""
Test de détection de l'hôte local
"""

from scanner import IPScanner
from utils import get_local_ip, get_network_range
import socket

def test_localhost_detection():
    """Teste la détection de l'hôte local"""

    print("=" * 60)
    print("TEST DE DÉTECTION DE L'HÔTE LOCAL")
    print("=" * 60)

    # Informations système
    local_ip = get_local_ip()
    hostname = socket.gethostname()
    network = get_network_range()

    print(f"\nInformations locales:")
    print(f"  IP locale: {local_ip}")
    print(f"  Hostname: {hostname}")
    print(f"  Réseau: {network}")

    # Créer le scanner
    scanner = IPScanner()

    # Tester la détection
    print(f"\nTest de is_local_host:")
    print(f"  {local_ip} -> {scanner.is_local_host(local_ip)}")
    print(f"  127.0.0.1 -> {scanner.is_local_host('127.0.0.1')}")
    print(f"  192.168.1.1 -> {scanner.is_local_host('192.168.1.1')}")

    # Tester la récupération de MAC
    print(f"\nRécupération MAC locale:")
    mac = scanner._get_local_mac_address()
    print(f"  MAC: {mac}")

    # Tester le scan de l'hôte local
    print(f"\nScan de l'hôte local ({local_ip})...")
    scan_config = scanner.get_quick_scan_config()
    scanner.is_running = True  # Important pour permettre le scan
    result = scanner.scan_host(local_ip, scan_config)

    if result:
        print("\n✅ SUCCÈS - Hôte local détecté!")
        print(f"\nRésultat du scan:")
        print(f"  IP: {result['ip']}")
        print(f"  Hostname: {result['hostname']}")
        print(f"  MAC: {result['mac']}")
        print(f"  OS: {result['os']}")
        print(f"  Status: {result['status']}")
        print(f"  Response time: {result['response_time']} ms")
    else:
        print("\n❌ ÉCHEC - Hôte local non détecté!")
        print("Vérifiez la configuration réseau")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_localhost_detection()
