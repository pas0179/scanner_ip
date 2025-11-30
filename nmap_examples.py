#!/usr/bin/env python3
"""
Exemples d'utilisation des scans Nmap avancés

Ce fichier montre comment utiliser les nouvelles fonctionnalités de scan Nmap :
- Presets de scan pré-configurés
- Options avancées personnalisées
- Sauvegarde des résultats
- Plages de ports personnalisées
"""

import logging
from nmap_advanced import (
    run_nmap_advanced_scan,
    get_preset_options,
    list_presets,
    format_nmap_results_summary
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_1_preset_quick():
    """
    Exemple 1: Utiliser un preset "quick" pour un scan rapide
    Équivalent à: nmap -sS -T4 -p 1-1000 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 1: Scan Rapide avec Preset")
    print("="*70)

    target_ip = "192.168.1.68"

    # Récupérer les options du preset 'quick'
    nmap_options = get_preset_options('quick')

    print(f"Options utilisées: {nmap_options}")
    print(f"\nLancement du scan rapide sur {target_ip}...")

    # Lancer le scan
    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,  # Les ports sont définis dans port_range
        nmap_options=nmap_options
    )

    print(f"\nRésultats: {format_nmap_results_summary(result)}")
    if result.get('error'):
        print(f"Erreur: {result['error']}")


def example_2_preset_standard_with_save():
    """
    Exemple 2: Scan standard avec sauvegarde des résultats
    Équivalent à: nmap -sS -p 1-1000 -T4 -sV -O -oA rapport_cible 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 2: Scan Standard avec Sauvegarde (Comme votre exemple)")
    print("="*70)

    target_ip = "192.168.1.68"
    output_file = "rapport_cible"

    # Récupérer les options du preset 'standard'
    nmap_options = get_preset_options('standard')

    print(f"Options utilisées: {nmap_options}")
    print(f"\nLancement du scan standard sur {target_ip}...")
    print(f"Sauvegarde dans: {output_file}.{{nmap,xml,gnmap}}")

    # Lancer le scan avec sauvegarde
    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,
        nmap_options=nmap_options,
        output_file=output_file  # Sauvegarde avec -oA
    )

    print(f"\nRésultats: {format_nmap_results_summary(result)}")
    if result.get('output_files'):
        print(f"Fichiers créés: {', '.join(result['output_files'])}")
    if result.get('error'):
        print(f"Erreur: {result['error']}")


def example_3_custom_options():
    """
    Exemple 3: Options personnalisées avancées
    Équivalent à: nmap -sS -sV -O -T4 -p 1-1000,8080,9000 --script vuln --traceroute 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 3: Scan Personnalisé avec Options Avancées")
    print("="*70)

    target_ip = "192.168.1.68"

    # Options personnalisées
    nmap_options = {
        'scan_type': 'syn',
        'timing': 'T4',
        'os_detection': True,
        'version_detection': True,
        'version_intensity': 9,
        'script_scan': 'vuln',  # Scripts de détection de vulnérabilités
        'traceroute': True,
        'port_range': '1-1000,8080,9000',  # Plage personnalisée
        'reason': True,
        'fragment_packets': False,
        'randomize_hosts': False
    }

    print(f"Options utilisées: {nmap_options}")
    print(f"\nLancement du scan personnalisé sur {target_ip}...")

    # Lancer le scan
    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,
        nmap_options=nmap_options,
        output_file="scan_custom"
    )

    print(f"\nRésultats: {format_nmap_results_summary(result)}")

    # Afficher les ports détaillés
    if result.get('detailed_ports'):
        print(f"\nPorts ouverts trouvés: {len(result['detailed_ports'])}")
        for port_info in result['detailed_ports'][:5]:  # Afficher les 5 premiers
            print(f"  - Port {port_info['port']}/{port_info['protocol']}: {port_info['service'].get('name', 'unknown')}")

    if result.get('error'):
        print(f"Erreur: {result['error']}")


def example_4_comprehensive_scan():
    """
    Exemple 4: Scan complet avec tous les ports
    Équivalent à: nmap -sS -A -T4 -p 1-65535 --script default,vuln -oA scan_complet 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 4: Scan Complet (ATTENTION: Peut être très long!)")
    print("="*70)

    # Récupérer les options du preset 'comprehensive'
    nmap_options = get_preset_options('comprehensive')

    print(f"Options utilisées: {nmap_options}")
    print(f"\nCe scan peut prendre plusieurs minutes voire heures!")
    print("Lancez uniquement si vous êtes sûr!")
    print("Pour lancer ce scan, décommentez le code ci-dessous")

    # Note: Commenté par défaut pour éviter les scans trop longs
    # target_ip = "192.168.1.68"
    # result = run_nmap_advanced_scan(
    #     ip=target_ip,
    #     ports=None,
    #     nmap_options=nmap_options,
    #     output_file="scan_complet"
    # )


def example_5_stealth_scan():
    """
    Exemple 5: Scan furtif discret
    Équivalent à: nmap -sS -T2 -f --randomize-hosts -p 1-1000 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 5: Scan Furtif (Lent et Discret)")
    print("="*70)

    target_ip = "192.168.1.68"

    # Récupérer les options du preset 'stealth'
    nmap_options = get_preset_options('stealth')

    print(f"Options utilisées: {nmap_options}")
    print(f"\nCe scan est lent mais discret pour éviter la détection")

    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,
        nmap_options=nmap_options
    )

    print(f"\nRésultats: {format_nmap_results_summary(result)}")
    if result.get('error'):
        print(f"Erreur: {result['error']}")


def example_6_udp_scan():
    """
    Exemple 6: Scan UDP des ports communs
    Équivalent à: sudo nmap -sU -T4 -sV -p 53,67,123,161,... 192.168.1.68
    """
    print("\n" + "="*70)
    print("EXEMPLE 6: Scan UDP (Nécessite ROOT)")
    print("="*70)

    target_ip = "192.168.1.68"

    # Récupérer les options du preset 'udp_scan'
    nmap_options = get_preset_options('udp_scan')

    print(f"Options utilisées: {nmap_options}")
    print(f"\nLancement du scan UDP sur {target_ip}...")
    print("Note: Les scans UDP sont généralement plus lents")

    # Lancer le scan (peut nécessiter sudo_password)
    result = run_nmap_advanced_scan(
        ip=target_ip,
        ports=None,
        nmap_options=nmap_options,
        # sudo_password="your_password"  # Décommenter si nécessaire
    )

    print(f"\nRésultats: {format_nmap_results_summary(result)}")
    if result.get('error'):
        print(f"Erreur: {result['error']}")


def list_all_presets():
    """
    Affiche tous les presets disponibles
    """
    print("\n" + "="*70)
    print("PRESETS DISPONIBLES")
    print("="*70)

    presets = list_presets()
    for preset in presets:
        print(f"\n🔹 {preset['key'].upper()}")
        print(f"   Nom: {preset['name']}")
        print(f"   Description: {preset['description']}")


def main():
    """
    Fonction principale pour tester les exemples
    """
    print("\n" + "#"*70)
    print("# EXEMPLES DE SCANS NMAP AVANCÉS")
    print("#"*70)

    # Afficher les presets disponibles
    list_all_presets()

    # Note: Changez l'IP cible avant de lancer les exemples!
    print("\n\n⚠️  ATTENTION: Changez l'IP cible (192.168.1.68) avant de lancer les exemples!")
    print("⚠️  Certains scans nécessitent les droits root (sudo)")
    print("⚠️  Assurez-vous d'avoir l'autorisation de scanner la cible!")

    # Décommentez les exemples que vous voulez tester:

    # example_1_preset_quick()
    # example_2_preset_standard_with_save()
    # example_3_custom_options()
    # example_4_comprehensive_scan()  # ATTENTION: Très long!
    # example_5_stealth_scan()
    # example_6_udp_scan()

    print("\n\nPour lancer les exemples, décommentez les lignes dans la fonction main()")


if __name__ == "__main__":
    main()
