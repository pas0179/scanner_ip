# Scanner IP Local

Scanner réseau avancé avec interface graphique Tkinter pour analyser votre réseau local.

## Fonctionnalités

### Scan Réseau
- **Scan Rapide**: Détection des hôtes actifs par ping
- **Scan Normal**: Détection + scan des ports communs
- **Scan Approfondi**: Analyse complète (tous les ports, OS, services)
- **Scan Personnalisé**: Configuration sur mesure

### Détection
- ✅ Détection d'hôtes actifs (ping ICMP)
- ✅ Récupération des noms d'hôte
- ✅ Récupération des adresses MAC (avec sudo)
- ✅ Détection du système d'exploitation (basée sur TTL)
- ✅ Scan de ports TCP (connexion ou SYN scan avec sudo)
- ✅ Détection de services
- ✅ Récupération de bannières

### Interface
- Interface graphique intuitive avec Tkinter
- Tableau de résultats triable
- Barre de progression en temps réel
- Export des résultats (CSV, JSON, XML, HTML)
- Historique des scans
- Menu contextuel (copier IP/MAC, détails)

### Architecture
Le projet est organisé en classes pour une meilleure maintenabilité:
- `MainWindow` (gui.py): Interface graphique
- `IPScanner` (scanner.py): Logique de scan
- `ScanThread` (scan_thread.py): Gestion du threading
- Modules utilitaires (utils.py, config.py)

## Installation

### Prérequis
- Python 3.7 ou supérieur
- Privilèges root/sudo (recommandé pour toutes les fonctionnalités)
- Linux, macOS ou Windows

### Dépendances système

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk libpcap-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip python3-tkinter libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip tk libpcap
```

**macOS:**
```bash
brew install python-tk libpcap
```

**Windows:**
- Installez Python depuis python.org (tkinter inclus)
- Installez Npcap: https://npcap.com/

### Installation des dépendances Python

```bash
# Cloner ou télécharger le projet
cd Scanner_IP

# Créer un environnement virtuel (optionnel mais recommandé)
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Lancement

**Mode normal (fonctionnalités limitées):**
```bash
python3 main.py
```

**Mode avec privilèges root (recommandé):**
```bash
sudo python3 main.py
```

### Fonctionnalités selon les privilèges

| Fonctionnalité | Sans sudo | Avec sudo |
|----------------|-----------|-----------|
| Ping ICMP | ✅ (via système) | ✅ (via Scapy) |
| Nom d'hôte | ✅ | ✅ |
| Adresse MAC | ⚠️ (limitée) | ✅ (ARP scan) |
| Scan ports | ✅ (connexion TCP) | ✅ (SYN scan) |
| Détection OS | ✅ | ✅ |
| Détection services | ✅ | ✅ |

### Guide d'utilisation

1. **Lancer l'application**
   ```bash
   sudo python3 main.py
   ```

2. **Configuration du scan**
   - La plage réseau est détectée automatiquement
   - Cliquez sur "Détecter" pour actualiser
   - Choisissez le type de scan:
     - **Quick**: Scan rapide (ping uniquement)
     - **Normal**: Scan standard (ping + ports communs)
     - **Deep**: Scan approfondi (tous les ports + détection avancée)
     - **Custom**: Configuration personnalisée

3. **Démarrer le scan**
   - Cliquez sur "Démarrer le Scan"
   - Suivez la progression dans la barre de statut
   - Les résultats s'affichent en temps réel

4. **Exploiter les résultats**
   - Double-cliquez sur une ligne pour voir les détails
   - Clic droit pour copier IP/MAC
   - Triez les colonnes en cliquant sur les en-têtes
   - Exportez les résultats au format souhaité

5. **Export et historique**
   - Bouton "Exporter": Sauvegarde au format CSV, JSON, XML ou HTML
   - Bouton "Historique": Consulte les scans précédents
   - Les fichiers sont sauvegardés dans le dossier `exports/`

## Exemples de scans

### Scan rapide d'un réseau /24
```
Plage: 192.168.1.0/24
Type: Quick
Durée: ~10-30 secondes
Résultat: Liste des hôtes actifs avec MAC et hostname
```

### Scan complet avec détection de services
```
Plage: 192.168.1.0/24
Type: Deep
Durée: ~5-15 minutes
Résultat: Hôtes + ports ouverts + services + OS
```

### Scan personnalisé de ports spécifiques
```
Plage: 192.168.1.100/32
Type: Custom
Ports: 22,80,443,3000-3010
Options: Détection OS + Services
```

## Structure du projet

```
Scanner_IP/
├── main.py              # Point d'entrée
├── gui.py               # Interface graphique (classe MainWindow)
├── scanner.py           # Logique de scan (classe IPScanner)
├── scan_thread.py       # Threading (classe ScanThread)
├── utils.py             # Fonctions utilitaires
├── config.py            # Configuration
├── requirements.txt     # Dépendances Python
├── README.md           # Documentation
├── exports/            # Exports de résultats
├── history/            # Historique des scans
└── logs/               # Logs d'exécution
```

## Configuration avancée

Modifiez `config.py` pour personnaliser:

- **Ports à scanner**: `COMMON_PORTS`, `EXTENDED_PORTS`
- **Timeouts**: `DEFAULT_TIMEOUT`, `PING_TIMEOUT`
- **Threads**: `MAX_THREADS`
- **Couleurs**: `THEME_COLOR`, `ACCENT_COLOR`, etc.
- **Exports**: `DEFAULT_EXPORT_FORMAT`

## Dépannage

### "Permission denied" lors du scan
**Solution**: Exécutez avec sudo
```bash
sudo python3 main.py
```

### "Module tkinter not found"
**Solution Ubuntu/Debian**:
```bash
sudo apt-get install python3-tk
```

### Scapy ne fonctionne pas
**Solution**: Vérifiez libpcap
```bash
sudo apt-get install libpcap-dev  # Ubuntu/Debian
```

### Scan très lent
**Solutions**:
- Réduisez la plage réseau
- Utilisez le scan "Quick" au lieu de "Deep"
- Augmentez `MAX_THREADS` dans config.py
- Exécutez avec sudo pour des scans plus rapides

### Adresses MAC non détectées
**Solution**: Exécutez avec sudo pour activer les scans ARP
```bash
sudo python3 main.py
```

## Sécurité et éthique

⚠️ **ATTENTION**:
- N'utilisez ce scanner QUE sur des réseaux dont vous êtes propriétaire ou pour lesquels vous avez l'autorisation
- Le scan de réseaux sans autorisation est illégal dans de nombreux pays
- Ce tool est destiné à des fins éducatives et d'administration réseau légitime

## Améliorations futures

- [ ] Support IPv6
- [ ] Scan UDP
- [ ] Détection de vulnérabilités
- [ ] Graphiques et visualisations
- [ ] Notifications de changements réseau
- [ ] Support SNMP
- [ ] Détection de duplicata IP
- [ ] Mode ligne de commande (CLI)
- [ ] API REST

## Contributeurs

Scanner IP Local - Projet éducatif Python/Tkinter

## Licence

Ce projet est fourni à des fins éducatives. Utilisez-le de manière responsable et légale.

## Support

Pour signaler un bug ou demander une fonctionnalité, créez une issue sur le dépôt du projet.

---

**Bon scan!** 🔍🌐
