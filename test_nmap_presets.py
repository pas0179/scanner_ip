#!/usr/bin/env python3
"""
Script de test pour vérifier que les presets Nmap fonctionnent correctement
"""

from nmap_advanced import list_presets, get_preset_options, NMAP_SCAN_PRESETS


def test_list_presets():
    """Test de listage des presets"""
    print("\n" + "="*70)
    print("TEST 1: Listage des presets")
    print("="*70)

    presets = list_presets()
    print(f"\n✅ {len(presets)} presets disponibles:\n")

    for preset in presets:
        print(f"  🔹 {preset['key']:15} - {preset['name']:20} : {preset['description']}")

    assert len(presets) == 6, "Il devrait y avoir 6 presets"
    print("\n✅ Test réussi!")


def test_get_preset_options():
    """Test de récupération des options d'un preset"""
    print("\n" + "="*70)
    print("TEST 2: Récupération des options du preset 'standard'")
    print("="*70)

    options = get_preset_options('standard')

    print("\nOptions récupérées:")
    for key, value in options.items():
        print(f"  {key:20} : {value}")

    # Vérifications
    assert options['scan_type'] == 'syn', "Le type de scan devrait être 'syn'"
    assert options['timing'] == 'T4', "Le timing devrait être 'T4'"
    assert options['os_detection'] == True, "La détection OS devrait être activée"
    assert options['version_detection'] == True, "La détection de version devrait être activée"
    assert options['port_range'] == '1-1000', "La plage de ports devrait être '1-1000'"

    print("\n✅ Test réussi!")


def test_preset_comprehensive():
    """Test du preset comprehensive"""
    print("\n" + "="*70)
    print("TEST 3: Preset 'comprehensive'")
    print("="*70)

    options = get_preset_options('comprehensive')

    print("\nOptions du scan complet:")
    for key, value in options.items():
        print(f"  {key:20} : {value}")

    assert options['port_range'] == '1-65535', "Devrait scanner tous les ports"
    assert options['traceroute'] == True, "Traceroute devrait être activé"
    assert 'vuln' in str(options.get('script_scan', '')), "Les scripts vuln devraient être activés"

    print("\n✅ Test réussi!")


def test_preset_stealth():
    """Test du preset stealth"""
    print("\n" + "="*70)
    print("TEST 4: Preset 'stealth'")
    print("="*70)

    options = get_preset_options('stealth')

    print("\nOptions du scan furtif:")
    for key, value in options.items():
        print(f"  {key:20} : {value}")

    assert options['timing'] == 'T2', "Le timing devrait être lent (T2)"
    assert options['fragment_packets'] == True, "La fragmentation devrait être activée"
    assert options['randomize_hosts'] == True, "La randomisation devrait être activée"

    print("\n✅ Test réussi!")


def test_preset_udp():
    """Test du preset UDP"""
    print("\n" + "="*70)
    print("TEST 5: Preset 'udp_scan'")
    print("="*70)

    options = get_preset_options('udp_scan')

    print("\nOptions du scan UDP:")
    for key, value in options.items():
        print(f"  {key:20} : {value}")

    assert options['scan_type'] == 'udp', "Le type devrait être UDP"
    assert '53' in options['port_range'], "Le port DNS (53) devrait être dans la liste"

    print("\n✅ Test réussi!")


def test_invalid_preset():
    """Test avec un preset invalide"""
    print("\n" + "="*70)
    print("TEST 6: Preset invalide (devrait retourner 'standard')")
    print("="*70)

    options = get_preset_options('invalid_preset_name')

    print("\nOptions retournées (devrait être 'standard'):")
    for key, value in options.items():
        print(f"  {key:20} : {value}")

    assert options['scan_type'] == 'syn', "Devrait retourner le preset 'standard'"

    print("\n✅ Test réussi!")


def display_all_presets():
    """Affiche tous les presets en détail"""
    print("\n" + "="*70)
    print("DÉTAIL DE TOUS LES PRESETS")
    print("="*70)

    for preset_key, preset_data in NMAP_SCAN_PRESETS.items():
        print(f"\n{'='*70}")
        print(f"Preset: {preset_key.upper()}")
        print(f"Nom: {preset_data['name']}")
        print(f"Description: {preset_data['description']}")
        print(f"{'-'*70}")
        print("Options:")
        for option_key, option_value in preset_data['options'].items():
            print(f"  {option_key:25} : {option_value}")


def main():
    """Fonction principale de test"""
    print("\n" + "#"*70)
    print("# TEST DES PRESETS NMAP")
    print("#"*70)

    try:
        # Tests unitaires
        test_list_presets()
        test_get_preset_options()
        test_preset_comprehensive()
        test_preset_stealth()
        test_preset_udp()
        test_invalid_preset()

        # Affichage détaillé
        display_all_presets()

        print("\n" + "="*70)
        print("✅ TOUS LES TESTS SONT RÉUSSIS!")
        print("="*70)
        print("\nLes presets Nmap sont prêts à être utilisés.")
        print("Vous pouvez maintenant utiliser:")
        print("  - quick_nmap_scan.py pour un scan rapide")
        print("  - nmap_examples.py pour des exemples avancés")
        print("  - ou intégrer directement dans votre code\n")

    except AssertionError as e:
        print(f"\n❌ ERREUR DE TEST: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERREUR INATTENDUE: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
