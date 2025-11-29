#!/bin/bash

# Script de lancement du Scanner IP

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         Scanner IP Local - Script de lancement           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Vérifier si l'environnement virtuel existe
if [ ! -d ".venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv .venv
    echo "✓ Environnement virtuel créé"
fi

# Activer l'environnement virtuel
echo "Activation de l'environnement virtuel..."
source .venv/bin/activate

# Vérifier si les dépendances sont installées
if ! python -c "import scapy" 2>/dev/null; then
    echo "Installation des dépendances..."
    pip install -r requirements.txt
    echo "✓ Dépendances installées"
fi

echo ""
echo "Lancement du Scanner IP..."
echo ""

# Vérifier si on est root
if [ "$EUID" -ne 0 ]; then
    echo "⚠  ATTENTION: Non exécuté en tant que root"
    echo "   Certaines fonctionnalités seront limitées"
    echo ""
    echo "   Pour toutes les fonctionnalités, exécutez:"
    echo "   sudo ./run.sh"
    echo ""
fi

# Lancer l'application
python3 main.py
