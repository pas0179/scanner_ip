#!/usr/bin/env python3
"""
Script de test de l'installation du Scanner IP
"""

import sys

def test_imports():
    """Teste tous les imports nécessaires"""
    print("Test des imports Python...")
    errors = []

    # Test des modules standards
    try:
        import tkinter
        print("  ✓ tkinter")
    except ImportError as e:
        errors.append(("tkinter", "Installez avec: sudo apt-get install python3-tk"))

    # Test des modules pip
    try:
        import scapy
        print("  ✓ scapy")
    except ImportError:
        errors.append(("scapy", "Installez avec: pip install scapy"))

    try:
        import netifaces
        print("  ✓ netifaces")
    except ImportError:
        errors.append(("netifaces", "Installez avec: pip install netifaces"))

    # Test des modules du projet
    try:
        import config
        print("  ✓ config")
    except ImportError as e:
        errors.append(("config", str(e)))

    try:
        import utils
        print("  ✓ utils")
    except ImportError as e:
        errors.append(("utils", str(e)))

    try:
        import scanner
        print("  ✓ scanner")
    except ImportError as e:
        errors.append(("scanner", str(e)))

    try:
        import scan_thread
        print("  ✓ scan_thread")
    except ImportError as e:
        errors.append(("scan_thread", str(e)))

    try:
        import gui
        print("  ✓ gui")
    except ImportError as e:
        errors.append(("gui", str(e)))

    return errors


def test_functionality():
    """Teste les fonctionnalités de base"""
    print("\nTest des fonctionnalités de base...")

    try:
        from utils import get_local_ip, get_network_range, validate_ip, is_root

        # Test détection IP
        local_ip = get_local_ip()
        print(f"  ✓ Détection IP locale: {local_ip}")

        # Test plage réseau
        network = get_network_range()
        print(f"  ✓ Détection réseau: {network}")

        # Test validation IP
        assert validate_ip("192.168.1.1") == True
        assert validate_ip("invalid") == False
        print("  ✓ Validation IP")

        # Test privilèges
        has_root = is_root()
        if has_root:
            print("  ✓ Privilèges root détectés")
        else:
            print("  ⚠ Pas de privilèges root (certaines fonctionnalités limitées)")

        return []
    except Exception as e:
        return [("Fonctionnalités", str(e))]


def test_directories():
    """Teste la création des répertoires"""
    print("\nTest de la structure des répertoires...")
    from pathlib import Path

    errors = []
    base_dir = Path(__file__).parent

    required_dirs = ['exports', 'history', 'logs']
    for dir_name in required_dirs:
        dir_path = base_dir / dir_name
        if dir_path.exists():
            print(f"  ✓ {dir_name}/")
        else:
            errors.append((dir_name, "Répertoire non créé"))

    return errors


def main():
    """Fonction principale de test"""
    print("=" * 60)
    print("TEST D'INSTALLATION - SCANNER IP LOCAL")
    print("=" * 60)
    print()

    all_errors = []

    # Test imports
    errors = test_imports()
    all_errors.extend(errors)

    # Test fonctionnalités
    errors = test_functionality()
    all_errors.extend(errors)

    # Test répertoires
    errors = test_directories()
    all_errors.extend(errors)

    # Résumé
    print("\n" + "=" * 60)
    if all_errors:
        print("❌ ÉCHEC - Erreurs détectées:")
        print("=" * 60)
        for module, error in all_errors:
            print(f"\n{module}:")
            print(f"  {error}")
        print("\n" + "=" * 60)
        return 1
    else:
        print("✅ SUCCÈS - Installation complète et fonctionnelle!")
        print("=" * 60)
        print("\nVous pouvez maintenant lancer l'application:")
        print("  python3 main.py")
        print("ou")
        print("  sudo python3 main.py  (recommandé)")
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
