#!/usr/bin/env python3
"""
Script de test pour le scanner WiFi
ATTENTION: Nécessite ROOT/SUDO
"""

import os
import sys
from wifi_scanner import WiFiScanner, WiFiNetwork
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def callback_progress(message: str, progress: int):
    """Callback pour afficher la progression"""
    print(f"[{progress:3d}%] {message}")


def main():
    """Fonction principale de test"""

    # Vérifier les droits root
    if os.geteuid() != 0:
        print("❌ Ce script nécessite les droits ROOT/SUDO")
        print("   Exécutez: sudo python3 test_wifi_scanner.py")
        sys.exit(1)

    print("=" * 60)
    print("TEST DU SCANNER WIFI")
    print("=" * 60)

    # Créer le scanner
    scanner = WiFiScanner(callback=callback_progress)

    # 1. Vérifier les dépendances
    print("\n1. Vérification des dépendances...")
    print("-" * 60)
    requirements = scanner.check_requirements()

    for req, available in requirements.items():
        status = "✓" if available else "✗"
        print(f"  {status} {req:<20} : {'Disponible' if available else 'Manquant'}")

    if not requirements['scapy']:
        print("\n❌ Scapy n'est pas disponible. Installation requise:")
        print("   pip install scapy")
        return

    # 2. Lister les interfaces WiFi
    print("\n2. Interfaces WiFi disponibles...")
    print("-" * 60)
    interfaces = scanner.get_wifi_interfaces()

    if not interfaces:
        print("❌ Aucune interface WiFi détectée")
        print("\nVérifiez que votre carte WiFi est bien connectée")
        return

    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")

    # Sélectionner la première interface
    selected_interface = interfaces[0]
    print(f"\n→ Interface sélectionnée: {selected_interface}")

    # 3. Activer le mode moniteur
    print("\n3. Activation du mode moniteur...")
    print("-" * 60)

    if not requirements['airmon_ng']:
        print("⚠️ airmon-ng non disponible, le mode moniteur peut ne pas fonctionner")
        print("\nPour installer:")
        print("  sudo apt-get install aircrack-ng")

        # Demander si on continue quand même
        response = input("\nContinuer quand même ? (o/N): ")
        if response.lower() != 'o':
            return

    mon_interface = scanner.enable_monitor_mode(selected_interface)

    if not mon_interface:
        print("❌ Échec de l'activation du mode moniteur")
        return

    print(f"✓ Mode moniteur activé: {mon_interface}")

    try:
        # 4. Scanner les réseaux WiFi
        print("\n4. Scan des réseaux WiFi...")
        print("-" * 60)

        if requirements['airodump_ng']:
            print("Utilisation de airodump-ng (scan de 30 secondes)...")
            networks = scanner.scan_networks_airodump(mon_interface, duration=30)

            if networks:
                print(f"\n✓ {len(networks)} réseaux détectés:\n")
                print(f"{'SSID':<20} {'BSSID':<20} {'Canal':<6} {'Signal':<8} {'Chiffrement'}")
                print("-" * 80)

                for net in sorted(networks, key=lambda x: x.signal_strength, reverse=True):
                    print(f"{net.ssid:<20} {net.bssid:<20} {net.channel:<6} "
                          f"{net.signal_strength:<8} {net.encryption}")
            else:
                print("⚠️ Aucun réseau détecté")

        else:
            print("⚠️ airodump-ng non disponible, scan basique uniquement")
            print("\nPour scanner les réseaux, installez:")
            print("  sudo apt-get install aircrack-ng")

        # 5. Test de capture de handshake (optionnel)
        print("\n5. Test de capture de handshake...")
        print("-" * 60)
        print("⚠️ La capture de handshake nécessite:")
        print("   - Un réseau WiFi dont vous êtes propriétaire")
        print("   - Un client connecté au réseau")
        print("   - Ou une déconnexion/reconnexion d'un client")

        if networks:
            # Afficher les réseaux WPA/WPA2 (seuls compatibles)
            wpa_networks = [n for n in networks if 'WPA' in n.encryption]

            if wpa_networks:
                print(f"\n{len(wpa_networks)} réseau(x) WPA/WPA2 détecté(s)")

                response = input("\nVoulez-vous tester la capture d'un handshake ? (o/N): ")

                if response.lower() == 'o':
                    print("\nRéseaux disponibles:")
                    for i, net in enumerate(wpa_networks[:10], 1):
                        print(f"  {i}. {net.ssid} ({net.bssid}) - Canal {net.channel}")

                    try:
                        choice = int(input("\nChoisissez un réseau (1-{}): ".format(len(wpa_networks[:10]))))
                        if 1 <= choice <= len(wpa_networks[:10]):
                            target = wpa_networks[choice - 1]

                            output_file = f"/tmp/handshake_{target.bssid.replace(':', '')}.pcap"

                            print(f"\n→ Capture sur: {target.ssid} ({target.bssid})")
                            print(f"→ Canal: {target.channel}")
                            print(f"→ Durée: 60 secondes")
                            print(f"→ Sortie: {output_file}")
                            print("\n⏳ Démarrage de la capture...")
                            print("   TIP: Déconnectez/reconnectez un appareil au réseau pour accélérer")

                            success = scanner.capture_handshake_scapy(
                                bssid=target.bssid,
                                channel=target.channel,
                                interface=mon_interface,
                                duration=60,
                                output_file=output_file
                            )

                            if success:
                                print("\n✓ Handshake capturé avec succès!")

                                # Essayer d'extraire le hash
                                if requirements['aircrack_ng']:
                                    print("\n6. Extraction du hash...")
                                    print("-" * 60)

                                    hash_result = scanner.extract_hash_from_pcap(output_file)

                                    if hash_result:
                                        print(f"\n✓ Hash disponible dans: {hash_result}")
                                        print("\nVous pouvez maintenant utiliser hashcat:")
                                        print(f"  hashcat -m 22000 {hash_result} wordlist.txt")
                                        print("\nOu aircrack-ng:")
                                        print(f"  aircrack-ng -w wordlist.txt {output_file}")
                            else:
                                print("\n⚠️ Handshake non capturé")
                                print("   Essayez de déconnecter/reconnecter un client")

                    except ValueError:
                        print("❌ Choix invalide")
            else:
                print("⚠️ Aucun réseau WPA/WPA2 détecté")
        else:
            print("⚠️ Aucun réseau disponible pour le test")

    finally:
        # 7. Désactiver le mode moniteur
        print("\n7. Nettoyage...")
        print("-" * 60)
        scanner.disable_monitor_mode(mon_interface)
        print("✓ Mode moniteur désactivé")

    print("\n" + "=" * 60)
    print("TEST TERMINÉ")
    print("=" * 60)

    # Afficher les instructions d'installation si nécessaire
    if not all(requirements.values()):
        print("\n📝 INSTRUCTIONS D'INSTALLATION:")
        print(scanner.get_installation_instructions())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interruption par l'utilisateur")
        print("N'oubliez pas de désactiver le mode moniteur si nécessaire:")
        print("  sudo airmon-ng stop wlan0mon")
    except Exception as e:
        logger.error(f"Erreur: {e}", exc_info=True)
