#!/usr/bin/env python3
"""
Script simple pour lister les réseaux WiFi disponibles
Usage: sudo python3 list_wifi_networks.py
"""

import os
import sys
from wifi_scanner import WiFiScanner


def main():
    """Liste les réseaux WiFi"""

    # Vérifier ROOT
    if os.geteuid() != 0:
        print("❌ Ce script nécessite ROOT/SUDO")
        print(f"   Usage: sudo {sys.argv[0]}")
        sys.exit(1)

    print("=" * 80)
    print("LISTE DES RÉSEAUX WIFI DISPONIBLES")
    print("=" * 80)

    scanner = WiFiScanner()

    # Vérifier les dépendances
    requirements = scanner.check_requirements()

    if not requirements['airodump_ng']:
        print("❌ airodump-ng n'est pas installé")
        print("\nInstallez-le avec:")
        print("  sudo apt-get install aircrack-ng")
        sys.exit(1)

    # Détecter l'interface WiFi
    print("\n🔍 Détection de l'interface WiFi...")
    interfaces = scanner.get_wifi_interfaces()

    if not interfaces:
        print("❌ Aucune interface WiFi détectée")
        sys.exit(1)

    interface = interfaces[0]
    print(f"✓ Interface: {interface}")

    # Activer le mode moniteur
    print("\n📡 Activation du mode moniteur...")
    mon_interface = scanner.enable_monitor_mode(interface)

    if not mon_interface:
        print("❌ Échec activation mode moniteur")
        sys.exit(1)

    print(f"✓ Mode moniteur: {mon_interface}")

    try:
        # Scanner les réseaux
        print("\n🔍 Scan des réseaux WiFi (30 secondes)...")
        print("    Patientez...\n")

        networks = scanner.scan_networks_airodump(mon_interface, duration=30)

        if not networks:
            print("⚠️  Aucun réseau détecté")
            sys.exit(0)

        # Afficher les réseaux
        print(f"\n✓ {len(networks)} réseau(x) détecté(s):\n")
        print("=" * 80)

        # En-tête du tableau
        print(f"{'SSID':<25} {'BSSID':<18} {'Canal':<7} {'Signal':<9} {'Chiffrement':<15}")
        print("-" * 80)

        # Trier par puissance du signal (du plus fort au plus faible)
        networks.sort(key=lambda x: x.signal_strength, reverse=True)

        # Afficher chaque réseau
        for i, net in enumerate(networks, 1):
            # Couleur selon la puissance du signal (si terminal le supporte)
            signal = net.signal_strength
            if signal > -50:
                signal_icon = "📶🟢"  # Excellent
            elif signal > -60:
                signal_icon = "📶🟡"  # Bon
            elif signal > -70:
                signal_icon = "📶🟠"  # Moyen
            else:
                signal_icon = "📶🔴"  # Faible

            # Icône de sécurité
            if 'WPA' in net.encryption:
                security_icon = "🔒"
            elif 'WEP' in net.encryption:
                security_icon = "⚠️ "
            else:
                security_icon = "🔓"

            print(f"{net.ssid:<25} {net.bssid:<18} {net.channel:<7} "
                  f"{signal_icon} {net.signal_strength:<4} dBm  "
                  f"{security_icon} {net.encryption:<15}")

        print("=" * 80)

        # Statistiques
        wpa_count = sum(1 for n in networks if 'WPA' in n.encryption)
        open_count = sum(1 for n in networks if 'Open' in n.encryption or n.encryption == '')
        wep_count = sum(1 for n in networks if 'WEP' in n.encryption)

        print(f"\n📊 STATISTIQUES:")
        print(f"   Total: {len(networks)} réseaux")
        print(f"   🔒 WPA/WPA2/WPA3: {wpa_count}")
        print(f"   ⚠️  WEP (obsolète): {wep_count}")
        print(f"   🔓 Ouverts: {open_count}")

        # Afficher les réseaux WPA pour capture de handshake
        wpa_networks = [n for n in networks if 'WPA' in n.encryption]
        if wpa_networks:
            print(f"\n💡 RÉSEAUX COMPATIBLES POUR CAPTURE DE HANDSHAKE:")
            print(f"   {len(wpa_networks)} réseau(x) WPA/WPA2/WPA3 détecté(s)")
            print(f"\n   Pour capturer un handshake, utilisez:")
            for net in wpa_networks[:5]:  # Afficher les 5 premiers
                print(f"   sudo python3 quick_wifi_hash.py {net.bssid} {net.channel}  # {net.ssid}")

        print("\n" + "=" * 80)

    finally:
        # Désactiver le mode moniteur
        print("\n🧹 Nettoyage...")
        scanner.disable_monitor_mode(mon_interface)
        print("✓ Mode moniteur désactivé")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interruption")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
