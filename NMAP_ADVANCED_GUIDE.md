# Guide des Scans Nmap Avancés

Ce guide explique comment utiliser les fonctionnalités avancées de scan Nmap intégrées dans votre scanner IP.

## 🎯 Vue d'ensemble

Le module `nmap_advanced.py` fournit des capacités de scan réseau professionnelles avec :
- **Presets pré-configurés** pour différents types de scans
- **Options avancées personnalisables**
- **Sauvegarde automatique des résultats** (format nmap, XML, grepable)
- **Support complet de toutes les options Nmap**

---

## 📋 Presets disponibles

### 1. Quick (Rapide)
**Commande équivalente**: `nmap -sS -T4 -p 1-1000 <cible>`

Idéal pour un scan rapide des ports les plus communs.

```python
from nmap_advanced import get_preset_options, run_nmap_advanced_scan

options = get_preset_options('quick')
result = run_nmap_advanced_scan(ip="192.168.1.68", ports=None, nmap_options=options)
```

### 2. Standard (Recommandé)
**Commande équivalente**: `nmap -sS -p 1-1000 -T4 -sV -O --reason <cible>`

Scan équilibré avec détection de version et OS. **C'est celui qui correspond à votre exemple!**

```python
options = get_preset_options('standard')
result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=options,
    output_file="rapport_cible"  # Sauvegarde avec -oA
)
```

**Fichiers créés** :
- `rapport_cible.nmap` - Format texte lisible
- `rapport_cible.xml` - Format XML pour parsing
- `rapport_cible.gnmap` - Format grepable

### 3. Comprehensive (Complet)
**Commande équivalente**: `nmap -sS -A -T4 -p 1-65535 --script default,vuln --traceroute <cible>`

Scan exhaustif avec tous les ports. **Attention : Peut prendre des heures!**

```python
options = get_preset_options('comprehensive')
result = run_nmap_advanced_scan(ip="192.168.1.68", ports=None, nmap_options=options)
```

### 4. Stealth (Furtif)
**Commande équivalente**: `nmap -sS -T2 -p 1-1000 -f --randomize-hosts <cible>`

Scan lent et discret pour éviter la détection par les IDS/IPS.

```python
options = get_preset_options('stealth')
result = run_nmap_advanced_scan(ip="192.168.1.68", ports=None, nmap_options=options)
```

### 5. Aggressive (Agressif)
**Commande équivalente**: `nmap -A -T5 -p 1-10000 <cible>`

Scan très rapide et bruyant. Maximum de vitesse, minimum de discrétion.

```python
options = get_preset_options('aggressive')
result = run_nmap_advanced_scan(ip="192.168.1.68", ports=None, nmap_options=options)
```

### 6. UDP Scan
**Commande équivalente**: `sudo nmap -sU -T4 -sV -p 53,67,123,161,... <cible>`

Scan des ports UDP les plus communs. **Nécessite root!**

```python
options = get_preset_options('udp_scan')
result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=options,
    sudo_password="votre_mot_de_passe"  # Si nécessaire
)
```

---

## ⚙️ Options personnalisées

Vous pouvez créer vos propres configurations en spécifiant manuellement les options :

### Exemple de votre commande initiale

```python
nmap_options = {
    'scan_type': 'syn',              # -sS
    'timing': 'T4',                  # -T4
    'os_detection': True,            # -O
    'version_detection': True,       # -sV
    'port_range': '1-1000',         # -p 1-1000
    'reason': True                   # --reason
}

result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=nmap_options,
    output_file="rapport_cible"      # -oA rapport_cible
)
```

### Toutes les options disponibles

```python
nmap_options = {
    # Type de scan
    'scan_type': 'syn',              # Options: 'syn', 'tcp', 'udp', 'fin', 'null', 'xmas', 'aggressive'

    # Timing (vitesse)
    'timing': 'T4',                  # Options: 'T0' à 'T5'
                                     # T0 = Paranoid (ultra lent)
                                     # T1 = Sneaky (très lent)
                                     # T2 = Polite (lent)
                                     # T3 = Normal (défaut)
                                     # T4 = Aggressive (rapide)
                                     # T5 = Insane (très rapide)

    # Détection
    'os_detection': True,            # -O (nécessite root)
    'version_detection': True,       # -sV
    'version_intensity': 9,          # --version-intensity (0-9)

    # Scripts NSE
    'script_scan': 'default,vuln',   # --script (peut être False, True, ou une chaîne)
                                     # Options: 'default', 'vuln', 'exploit', 'discovery', etc.

    # Traceroute
    'traceroute': True,              # --traceroute

    # Ports
    'port_range': '1-1000,8080,9000', # -p (format personnalisé)
    # Exemples de port_range:
    # '1-1000'              - Plage continue
    # '22,80,443'           - Ports spécifiques
    # '1-1000,8080,9000'    - Combinaison
    # '1-65535'             - Tous les ports

    # Options avancées
    'reason': True,                  # --reason (afficher la raison de l'état du port)
    'fragment_packets': True,        # -f (fragmentation de paquets)
    'randomize_hosts': True,         # --randomize-hosts
}
```

---

## 💾 Sauvegarde des résultats

### Sauvegarde automatique avec -oA

```python
result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=options,
    output_file="/chemin/vers/rapport"  # Sans extension
)

# Fichiers créés automatiquement:
# - rapport.nmap  (format texte)
# - rapport.xml   (format XML)
# - rapport.gnmap (format grepable)

print(result['output_files'])
# ['rapport.nmap', 'rapport.xml', 'rapport.gnmap']
```

---

## 🔐 Utilisation avec sudo

Certaines options nécessitent les droits root :
- `-sS` (SYN scan)
- `-O` (détection OS)
- `-sU` (UDP scan)
- `--traceroute`

### Méthode 1 : Exécuter le script avec sudo

```bash
sudo python3 nmap_examples.py
```

### Méthode 2 : Passer le mot de passe sudo

```python
result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=options,
    sudo_password="votre_mot_de_passe"
)
```

---

## 📊 Exploitation des résultats

```python
result = run_nmap_advanced_scan(ip="192.168.1.68", ports=None, nmap_options=options)

# Détection OS
if result['os_details']:
    print(f"OS détecté: {result['os_details']['name']}")
    print(f"Précision: {result['os_details']['accuracy']}%")

# Ports ouverts
for port in result['detailed_ports']:
    print(f"Port {port['port']}/{port['protocol']} : {port['state']['state']}")
    if port['service']:
        print(f"  Service: {port['service']['name']}")
        print(f"  Version: {port['service']['version']}")

# Traceroute
if result['traceroute']:
    print("Route vers la cible:")
    for hop in result['traceroute']:
        print(f"  {hop['ttl']} - {hop['ip']} ({hop['host']}) - {hop['rtt']}ms")

# Scripts NSE
if result['scripts_output']:
    for script_name, output in result['scripts_output'].items():
        print(f"Script {script_name}:")
        print(output)

# Erreurs
if result['error']:
    print(f"Erreur: {result['error']}")
```

---

## 🎓 Exemples pratiques

### Exemple 1 : Scan rapide d'un réseau local
```python
from nmap_advanced import get_preset_options, run_nmap_advanced_scan

# Utiliser le preset 'quick'
options = get_preset_options('quick')

# Scanner plusieurs hôtes
targets = ["192.168.1.1", "192.168.1.10", "192.168.1.68"]

for target in targets:
    result = run_nmap_advanced_scan(ip=target, ports=None, nmap_options=options)
    print(f"{target}: {len(result['detailed_ports'])} ports ouverts")
```

### Exemple 2 : Scan de vulnérabilités
```python
# Configuration personnalisée pour détecter les vulnérabilités
vuln_options = {
    'scan_type': 'syn',
    'timing': 'T4',
    'os_detection': True,
    'version_detection': True,
    'version_intensity': 9,
    'script_scan': 'vuln,exploit',  # Scripts de vulnérabilités
    'port_range': '1-10000'
}

result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=vuln_options,
    output_file="scan_vulnerabilites"
)

# Analyser les résultats
for script_name, output in result['scripts_output'].items():
    if 'VULNERABLE' in output:
        print(f"⚠️  Vulnérabilité détectée: {script_name}")
        print(output)
```

### Exemple 3 : Scan furtif pour pentesting
```python
# Configuration furtive
stealth_options = {
    'scan_type': 'syn',
    'timing': 'T1',  # Très lent
    'os_detection': False,  # Pas de détection OS (bruyant)
    'version_detection': False,
    'script_scan': False,
    'port_range': '1-1024',
    'fragment_packets': True,  # Fragmenter les paquets
    'randomize_hosts': True    # Randomiser l'ordre
}

result = run_nmap_advanced_scan(
    ip="192.168.1.68",
    ports=None,
    nmap_options=stealth_options
)
```

---

## 📚 Référence rapide des commandes

| Preset | Commande équivalente | Temps estimé | Root requis |
|--------|---------------------|--------------|-------------|
| quick | `nmap -sS -T4 -p 1-1000` | ~30s | Oui |
| standard | `nmap -sS -T4 -sV -O -p 1-1000` | ~2min | Oui |
| comprehensive | `nmap -sS -A -T4 -p 1-65535` | ~30min+ | Oui |
| stealth | `nmap -sS -T2 -f -p 1-1000` | ~5min | Oui |
| aggressive | `nmap -A -T5 -p 1-10000` | ~1min | Oui |
| udp_scan | `nmap -sU -T4 -sV -p 53,67,123,...` | ~3min | Oui |

---

## ⚠️ Avertissements

1. **Légalité** : N'utilisez ces outils que sur des systèmes dont vous avez l'autorisation de scanner
2. **Performance** : Les scans complets peuvent saturer le réseau
3. **Détection** : Les scans agressifs peuvent déclencher des IDS/IPS
4. **Root** : La plupart des fonctionnalités avancées nécessitent les droits root

---

## 🔗 Ressources

- [Documentation officielle Nmap](https://nmap.org/book/man.html)
- [Guide des scripts NSE](https://nmap.org/nsedoc/)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)

---

## 🤝 Contribution

Pour ajouter de nouveaux presets ou options, modifiez le dictionnaire `NMAP_SCAN_PRESETS` dans `nmap_advanced.py`.
