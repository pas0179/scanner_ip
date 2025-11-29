# Guide de Démarrage Rapide - Scanner IP

## Installation en 3 étapes

### 1. Installer les dépendances système

```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip python3-tk libpcap-dev

# Fedora/RHEL
sudo dnf install python3 python3-pip python3-tkinter libpcap-devel

# Arch Linux
sudo pacman -S python python-pip tk libpcap
```

### 2. Installer les dépendances Python

```bash
# Activer l'environnement virtuel (déjà créé)
source .venv/bin/activate

# Installer les paquets
pip install -r requirements.txt
```

### 3. Lancer l'application

**Option A - Avec le script de lancement (recommandé):**
```bash
# Mode normal
./run.sh

# Avec privilèges root (toutes les fonctionnalités)
sudo ./run.sh
```

**Option B - Directement:**
```bash
# Mode normal
python3 main.py

# Avec privilèges root
sudo python3 main.py
```

## Utilisation Rapide

1. **Lancez l'application** avec `sudo ./run.sh`

2. **La plage réseau est auto-détectée** (ex: 192.168.1.0/24)

3. **Choisissez le type de scan:**
   - **Quick**: Rapide, ping uniquement (~30 sec)
   - **Normal**: Standard, ping + ports communs (~2 min)
   - **Deep**: Complet, tous les ports + détection (~10 min)
   - **Custom**: Personnalisé selon vos besoins

4. **Cliquez sur "Démarrer le Scan"**

5. **Consultez les résultats** en temps réel dans le tableau

6. **Exportez si nécessaire** (CSV, JSON, XML, HTML)

## Fonctionnalités Principales

| Fonction | Description | Raccourci |
|----------|-------------|-----------|
| Double-clic | Voir détails d'un hôte | Double-clic sur ligne |
| Clic droit | Menu contextuel | Clic droit sur ligne |
| Tri | Trier par colonne | Clic sur en-tête |
| Export | Sauvegarder résultats | Bouton "Exporter" |
| Historique | Voir scans précédents | Bouton "Historique" |

## Différence sudo vs non-sudo

| Fonctionnalité | Sans sudo | Avec sudo |
|----------------|-----------|-----------|
| Détection hôtes | ✅ | ✅ Plus rapide |
| Adresse MAC | ⚠️ Limité | ✅ Complet |
| Scan ports | ✅ TCP Connect | ✅ SYN Scan |
| Services | ✅ | ✅ |

## Exemples d'utilisation

### Scan rapide de votre réseau
```
Type: Quick
Temps: ~30 secondes
Résultat: Liste des appareils connectés
```

### Trouver les services exposés
```
Type: Normal
Temps: ~2-5 minutes
Résultat: Hôtes + ports ouverts + services
```

### Audit de sécurité complet
```
Type: Deep
Temps: ~10-15 minutes
Résultat: Analyse complète avec détection OS
```

### Scanner un hôte spécifique
```
Plage: 192.168.1.50/32
Type: Custom
Ports: 1-65535
```

## Dépannage Express

**Erreur "Permission denied"**
→ Lancez avec `sudo ./run.sh`

**Module tkinter introuvable**
→ `sudo apt-get install python3-tk`

**Scan trop lent**
→ Utilisez type "Quick" au lieu de "Deep"

**MAC non détectées**
→ Lancez avec sudo

## Structure du projet

```
Scanner_IP/
├── main.py          # Point d'entrée principal
├── gui.py           # Interface graphique
├── scanner.py       # Logique de scan
├── scan_thread.py   # Gestion threading
├── utils.py         # Utilitaires
├── config.py        # Configuration
├── run.sh           # Script de lancement
└── requirements.txt # Dépendances
```

## Support

Consultez le README.md pour la documentation complète.

Pour des questions ou problèmes, vérifiez:
1. Les logs dans `logs/scanner.log`
2. La documentation dans README.md
3. Les exports dans `exports/`

---

**Bon scan!** 🔍
