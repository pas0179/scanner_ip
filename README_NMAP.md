# 🔍 Scans Nmap Avancés - Guide de Démarrage Rapide

## 🚀 Démarrage rapide (Votre commande!)

Pour reproduire exactement votre commande :
```bash
nmap -sS -p 1-1000 -T4 -sV -O -oA rapport_cible 192.168.1.68
```

**Utilisez simplement** :
```bash
sudo python3 quick_nmap_scan.py 192.168.1.68
```

Cela va :
- ✅ Scanner les ports 1-1000 avec SYN scan (-sS)
- ✅ Utiliser le timing T4 (rapide)
- ✅ Détecter les versions de services (-sV)
- ✅ Détecter le système d'exploitation (-O)
- ✅ Sauvegarder les résultats dans 3 formats (-oA rapport_cible)

---

## 📁 Fichiers créés

Voici les nouveaux fichiers ajoutés à votre projet :

### Scripts principaux

1. **`quick_nmap_scan.py`** ⭐
   - Script simple pour lancer rapidement un scan comme votre exemple
   - Usage: `sudo python3 quick_nmap_scan.py <IP>`

2. **`nmap_examples.py`**
   - Fichier d'exemples avec 6 scénarios différents
   - Scans prédéfinis : rapide, standard, complet, furtif, agressif, UDP

### Modules améliorés

3. **`nmap_advanced.py`** (modifié)
   - Nouvelles options ajoutées :
     - Support de `-oA` pour sauvegarde multi-format
     - Types de scan : SYN, TCP, UDP, FIN, NULL, XMAS
     - Timing : T0 à T5
     - Scripts NSE personnalisés
     - Fragmentation de paquets
     - Et bien plus...

### Documentation

4. **`NMAP_ADVANCED_GUIDE.md`**
   - Guide complet de toutes les fonctionnalités
   - Exemples détaillés
   - Référence des options

5. **`README_NMAP.md`** (ce fichier)
   - Guide de démarrage rapide

---

## 💡 Exemples d'utilisation

### Exemple 1 : Scan rapide (votre commande)
```bash
sudo python3 quick_nmap_scan.py 192.168.1.68
```

### Exemple 2 : Utiliser un preset depuis Python
```python
from nmap_advanced import get_preset_options, run_nmap_advanced_scan

# Utiliser le preset "standard" (équivalent à votre commande)
options = get_preset_options('standard')

result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=options,
    output_file="rapport_cible"
)

print(f"Ports ouverts: {len(result['detailed_ports'])}")
```

### Exemple 3 : Options personnalisées
```python
from nmap_advanced import run_nmap_advanced_scan

# Configuration personnalisée
custom_options = {
    'scan_type': 'syn',
    'timing': 'T4',
    'os_detection': True,
    'version_detection': True,
    'port_range': '1-1000,8080,9000',  # Ports personnalisés
    'script_scan': 'vuln',  # Scripts de vulnérabilités
}

result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=custom_options,
    output_file="scan_custom"
)
```

---

## 🎯 Presets disponibles

| Preset | Description | Commande équivalente |
|--------|-------------|---------------------|
| **quick** | Scan rapide | `nmap -sS -T4 -p 1-1000` |
| **standard** | Votre exemple ⭐ | `nmap -sS -T4 -sV -O -p 1-1000` |
| **comprehensive** | Scan complet | `nmap -sS -A -T4 -p 1-65535` |
| **stealth** | Scan furtif | `nmap -sS -T2 -f -p 1-1000` |
| **aggressive** | Scan agressif | `nmap -A -T5 -p 1-10000` |
| **udp_scan** | Scan UDP | `nmap -sU -T4 -sV -p 53,67,...` |

---

## 📦 Options Nmap supportées

### Types de scan
- `-sS` : SYN scan (furtif, nécessite root)
- `-sT` : TCP Connect scan
- `-sU` : UDP scan
- `-sF` : FIN scan
- `-sN` : NULL scan
- `-sX` : XMAS scan
- `-A` : Scan agressif (OS + version + scripts + traceroute)

### Timing
- `T0` : Paranoid (ultra lent, très furtif)
- `T1` : Sneaky (très lent)
- `T2` : Polite (lent)
- `T3` : Normal (défaut)
- `T4` : Aggressive (rapide) ⭐
- `T5` : Insane (très rapide)

### Détection
- `-O` : Détection du système d'exploitation
- `-sV` : Détection des versions de services
- `--version-intensity <0-9>` : Intensité de la détection de version

### Scripts NSE
- `default` : Scripts par défaut
- `vuln` : Détection de vulnérabilités
- `exploit` : Scripts d'exploitation
- `discovery` : Découverte réseau
- `safe` : Scripts sûrs uniquement

### Options avancées
- `-oA <basename>` : Sauvegarde dans tous les formats
- `--traceroute` : Tracer la route
- `--reason` : Afficher la raison de l'état du port
- `-f` : Fragmentation de paquets
- `--randomize-hosts` : Randomiser l'ordre des hôtes

---

## 🔐 Permissions root

La plupart des scans avancés nécessitent les droits root :

```bash
# Méthode 1 : Utiliser sudo
sudo python3 quick_nmap_scan.py 192.168.1.68

# Méthode 2 : Donner les permissions à nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

---

## 💾 Formats de sauvegarde

Quand vous utilisez `output_file="rapport_cible"`, trois fichiers sont créés :

1. **`rapport_cible.nmap`** : Format texte lisible par l'humain
2. **`rapport_cible.xml`** : Format XML pour parsing automatique
3. **`rapport_cible.gnmap`** : Format grepable pour recherches

---

## 📊 Intégration dans l'interface graphique

Les nouvelles options sont déjà intégrées dans `gui.py` via la fenêtre "Deep Scan".

Pour les utiliser depuis l'interface :
1. Lancez l'application : `python3 gui.py`
2. Sélectionnez un hôte
3. Cliquez sur "Deep Scan"
4. Configurez les options Nmap
5. Lancez le scan

---

## ⚠️ Avertissements

1. **⚖️ Légalité** : N'utilisez ces outils que sur des systèmes dont vous avez l'autorisation
2. **🚦 Performances** : Les scans complets peuvent saturer le réseau
3. **🚨 Détection** : Les scans agressifs peuvent déclencher des IDS/IPS
4. **🔑 Root** : La plupart des fonctionnalités nécessitent les droits root

---

## 📚 Pour aller plus loin

- **Guide complet** : Consultez `NMAP_ADVANCED_GUIDE.md`
- **Exemples détaillés** : Voir `nmap_examples.py`
- **Documentation Nmap** : https://nmap.org/book/man.html

---

## 🐛 Dépannage

### Erreur "Permission denied"
```bash
# Solution : Utiliser sudo
sudo python3 quick_nmap_scan.py 192.168.1.68
```

### Erreur "nmap: command not found"
```bash
# Installer Nmap
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # CentOS/RHEL
```

### Le scan est très lent
```bash
# Utiliser un timing plus rapide (T4 ou T5)
# Ou réduire la plage de ports
```

---

## 🎓 Exemples de commandes équivalentes

| Python | Commande Nmap |
|--------|---------------|
| `get_preset_options('quick')` | `nmap -sS -T4 -p 1-1000` |
| `get_preset_options('standard')` | `nmap -sS -T4 -sV -O -p 1-1000` |
| `scan_type='udp'` | `nmap -sU` |
| `timing='T5'` | `nmap -T5` |
| `script_scan='vuln'` | `nmap --script vuln` |
| `output_file='rapport'` | `nmap -oA rapport` |

---

**Bon scan!** 🚀
