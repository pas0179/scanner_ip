#!/usr/bin/env python3
"""
Script rapide pour reproduire exactement la commande :
nmap -sS -p 1-1000 -T4 -sV -O -oA rapport_cible 192.168.1.68

Usage:
    sudo python3 quick_nmap_scan.py <IP_CIBLE>

Exemple:
    sudo python3 quick_nmap_scan.py 192.168.1.68
"""

import sys
import logging
from nmap_advanced import run_nmap_advanced_scan, format_nmap_results_summary

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """
    Fonction principale qui reproduit exactement :
    nmap -sS -p 1-1000 -T4 -sV -O -oA rapport_cible 192.168.1.68
    """

    # Vérifier les arguments
    if len(sys.argv) < 2:
        print("❌ Usage: sudo python3 quick_nmap_scan.py <IP_CIBLE>")
        print("   Exemple: sudo python3 quick_nmap_scan.py 192.168.1.68")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Configuration exacte de votre commande
    nmap_options = {
        'scan_type': 'syn',              # -sS
        'port_range': '1-1000',          # -p 1-1000
        'timing': 'T4',                  # -T4
        'version_detection': True,       # -sV
        'os_detection': True,            # -O
        'reason': True                   # Afficher la raison (bonus)
    }

    output_file = "rapport_cible"  # -oA rapport_cible

    print("\n" + "="*70)
    print(f"🔍 Scan Nmap de {target_ip}")
    print("="*70)
    print("\n📋 Configuration:")
    print(f"   Type de scan: SYN Scan (-sS)")
    print(f"   Ports: 1-1000")
    print(f"   Vitesse: T4 (Aggressive)")
    print(f"   Détection de version: Oui (-sV)")
    print(f"   Détection OS: Oui (-O)")
    print(f"   Sauvegarde: {output_file}.{{nmap,xml,gnmap}}")
    print("\n⏳ Lancement du scan (peut prendre quelques minutes)...\n")

    # Lancer le scan
    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,  # On utilise port_range à la place
        nmap_options=nmap_options,
        output_file=output_file
    )

    # Afficher les résultats
    print("\n" + "="*70)
    print("✅ Scan terminé!")
    print("="*70)

    # Vérifier les erreurs
    if result.get('error'):
        print(f"\n❌ Erreur: {result['error']}")
        return

    # Résumé
    print(f"\n📊 Résumé: {format_nmap_results_summary(result)}")

    # Détection OS
    if result.get('os_details'):
        os_info = result['os_details']
        print(f"\n🖥️  Système d'exploitation détecté:")
        print(f"   {os_info.get('name', 'Unknown')} (Précision: {os_info.get('accuracy', '0')}%)")
        if os_info.get('vendor'):
            print(f"   Vendeur: {os_info['vendor']}")
        if os_info.get('family'):
            print(f"   Famille: {os_info['family']}")

    # Ports ouverts
    if result.get('detailed_ports'):
        open_ports = [p for p in result['detailed_ports'] if p['state']['state'] == 'open']
        print(f"\n🔓 Ports ouverts: {len(open_ports)}")

        if open_ports:
            print("\n   Port  | État   | Service         | Version")
            print("   " + "-"*60)
            for port in open_ports[:20]:  # Afficher max 20 ports
                port_num = port['port']
                state = port['state']['state']
                service_name = port.get('service', {}).get('name', 'unknown')
                service_version = port.get('service', {}).get('version', '')
                service_product = port.get('service', {}).get('product', '')

                version_info = f"{service_product} {service_version}".strip()
                if not version_info:
                    version_info = "-"

                print(f"   {port_num:5} | {state:6} | {service_name:15} | {version_info}")

            if len(open_ports) > 20:
                print(f"\n   ... et {len(open_ports) - 20} autres ports")

    # Traceroute
    if result.get('traceroute'):
        print(f"\n🌐 Traceroute: {len(result['traceroute'])} sauts")

    # Scripts NSE
    if result.get('scripts_output'):
        print(f"\n📝 Scripts NSE exécutés: {len(result['scripts_output'])}")

    # Fichiers de sortie
    if result.get('output_files'):
        print(f"\n💾 Fichiers de résultats créés:")
        for file in result['output_files']:
            print(f"   ✓ {file}")

    print("\n" + "="*70)
    print("✨ Analyse terminée avec succès!")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrompu par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur inattendue: {e}", exc_info=True)
        sys.exit(1)
