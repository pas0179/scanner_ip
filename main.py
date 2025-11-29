#!/usr/bin/env python3
"""
Scanner IP Local - Point d'entrée principal
Outil de scan réseau avec interface graphique Tkinter

Usage:
    python3 main.py              # Mode normal
    sudo python3 main.py         # Mode avec privilèges root (recommandé)

Author: Scanner IP Team
"""

import sys
import os
import logging
from pathlib import Path

# Ajouter le répertoire courant au path
sys.path.insert(0, str(Path(__file__).parent))

from config import LOG_FILE, LOG_FORMAT, LOG_LEVEL
from utils import is_root
import gui


def setup_logging():
    """
    Configure le système de logging
    """
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )


def check_dependencies():
    """
    Vérifie que toutes les dépendances sont installées

    Returns:
        True si toutes les dépendances sont présentes, False sinon
    """
    missing_deps = []

    try:
        import tkinter
    except ImportError:
        missing_deps.append("tkinter (python3-tk)")

    try:
        import scapy
    except ImportError:
        missing_deps.append("scapy")

    try:
        import netifaces
    except ImportError:
        missing_deps.append("netifaces")

    if missing_deps:
        print("ERREUR: Dépendances manquantes:")
        print("\nInstallez les dépendances avec:")
        print("  pip install -r requirements.txt")

        if "tkinter" in str(missing_deps):
            print("\nPour tkinter sur Ubuntu/Debian:")
            print("  sudo apt-get install python3-tk")

        print("\nDépendances manquantes:")
        for dep in missing_deps:
            print(f"  - {dep}")

        return False

    return True


def print_banner():
    """
    Affiche la bannière de démarrage
    """
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SCANNER IP LOCAL v1.0                        ║
║              Analyse réseau avancée                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)

    if is_root():
        print("✓ Exécution avec privilèges root - Toutes les fonctionnalités activées")
    else:
        print("⚠ Exécution sans privilèges root - Fonctionnalités limitées")
        print("  Pour activer toutes les fonctionnalités: sudo python3 main.py")

    print("\nDémarrage de l'interface graphique...\n")


def main():
    """
    Fonction principale
    """
    # Configuration du logging
    setup_logging()
    logger = logging.getLogger(__name__)

    # Vérifier les dépendances
    if not check_dependencies():
        sys.exit(1)

    # Afficher la bannière
    print_banner()

    # Lancer l'interface graphique
    try:
        logger.info("Démarrage du Scanner IP")
        gui.run()
        logger.info("Arrêt du Scanner IP")

    except KeyboardInterrupt:
        print("\n\nInterruption par l'utilisateur")
        logger.info("Arrêt par Ctrl+C")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Erreur fatale: {e}", exc_info=True)
        print(f"\nErreur fatale: {e}")
        print("Consultez les logs pour plus de détails")
        sys.exit(1)


if __name__ == "__main__":
    main()
