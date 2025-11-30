# 📡 Scanner WiFi - Guide Rapide

## ✅ Oui, vous pouvez intégrer un scanner WiFi pour récupérer les hashs !

J'ai créé un module complet de scanner WiFi pour votre projet. Voici ce qui a été ajouté :

## 📦 Fichiers créés

### 1. **wifi_scanner.py** - Module principal
Le module complet avec toutes les fonctionnalités :
- Détection des interfaces WiFi
- Activation/désactivation du mode moniteur
- Scan des réseaux WiFi (SSID, BSSID, canal, chiffrement)
- Capture de handshakes WPA/WPA2
- Extraction des hashs pour hashcat/aircrack-ng

### 2. **test_wifi_scanner.py** - Script de test complet
Script interactif pour tester toutes les fonctionnalités :
```bash
sudo python3 test_wifi_scanner.py
```

### 3. **list_wifi_networks.py** - Lister les réseaux
Script simple pour scanner et afficher les réseaux WiFi :
```bash
sudo python3 list_wifi_networks.py
```

### 4. **quick_wifi_hash.py** - Capture rapide
Script pour capturer directement un handshake :
```bash
sudo python3 quick_wifi_hash.py AA:BB:CC:DD:EE:FF 6
```

### 5. **WIFI_INTEGRATION.md** - Documentation complète
Guide détaillé pour intégrer le scanner WiFi dans votre GUI.

## 🚀 Installation rapide

### 1. Installer les dépendances système
```bash
sudo apt-get update
sudo apt-get install aircrack-ng hcxtools
```

### 2. Vérifier l'installation
```bash
airmon-ng
airodump-ng --help
hcxpcapngtool --version
```

### 3. Tester immédiatement
```bash
# Lister les réseaux WiFi
sudo python3 list_wifi_networks.py
```

## 📖 Utilisation basique

### Scénario 1: Lister les réseaux WiFi disponibles

```bash
sudo python3 list_wifi_networks.py
```

Résultat :
```
SSID                      BSSID              Canal   Signal    Chiffrement
--------------------------------------------------------------------------------
MonWiFi                   AA:BB:CC:DD:EE:FF  6       📶🟢 -45 dBm  🔒 WPA2
WiFi-Voisin              11:22:33:44:55:66  11      📶🟡 -58 dBm  🔒 WPA2
Hotspot-Public           99:88:77:66:55:44  1       📶🔴 -75 dBm  🔓 Open
```

### Scénario 2: Capturer un handshake

```bash
# 1. Lister les réseaux d'abord
sudo python3 list_wifi_networks.py

# 2. Choisir un réseau (VOTRE réseau !)
#    Exemple: BSSID=AA:BB:CC:DD:EE:FF, Canal=6

# 3. Capturer le handshake
sudo python3 quick_wifi_hash.py AA:BB:CC:DD:EE:FF 6

# 4. Le hash sera sauvegardé automatiquement
```

### Scénario 3: Utiliser dans votre code Python

```python
from wifi_scanner import WiFiScanner

# Créer le scanner (nécessite sudo)
scanner = WiFiScanner()

# Lister les interfaces
interfaces = scanner.get_wifi_interfaces()
print(f"Interfaces: {interfaces}")

# Activer le mode moniteur
mon_interface = scanner.enable_monitor_mode('wlan0')

# Scanner les réseaux (30 secondes)
networks = scanner.scan_networks_airodump(mon_interface, duration=30)

for net in networks:
    print(f"{net.ssid} - {net.bssid} - Canal {net.channel} - {net.encryption}")

# Capturer un handshake
success = scanner.capture_handshake_scapy(
    bssid='AA:BB:CC:DD:EE:FF',
    channel=6,
    interface=mon_interface,
    output_file='/tmp/handshake.pcap'
)

if success:
    # Extraire le hash
    hash_value = scanner.extract_hash_from_pcap('/tmp/handshake.pcap')
    print(f"Hash: {hash_value}")

# Désactiver le mode moniteur
scanner.disable_monitor_mode(mon_interface)
```

## 🎯 Workflow complet

```
┌─────────────────────────────────────────────────────────────┐
│  1. SCANNER LES RÉSEAUX                                     │
│     sudo python3 list_wifi_networks.py                      │
│     → Identifie SSID, BSSID, Canal, Chiffrement             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  2. CAPTURER LE HANDSHAKE (sur VOTRE réseau)                │
│     sudo python3 quick_wifi_hash.py [BSSID] [CANAL]         │
│     → Capture le handshake 4-way                            │
│     → Sauvegarde en .pcap et extrait le hash                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  3. CRACKER LE HASH (test de sécurité de VOTRE réseau)      │
│     hashcat -m 22000 hash.hc22000 rockyou.txt               │
│     OU                                                       │
│     aircrack-ng -w rockyou.txt handshake.pcap               │
└─────────────────────────────────────────────────────────────┘
```

## ⚙️ Fonctionnalités du module

### WiFiScanner - Méthodes principales

| Méthode | Description |
|---------|-------------|
| `get_wifi_interfaces()` | Liste les interfaces WiFi disponibles |
| `enable_monitor_mode(interface)` | Active le mode moniteur |
| `disable_monitor_mode(interface)` | Désactive le mode moniteur |
| `scan_networks_airodump(interface, duration)` | Scanne les réseaux WiFi |
| `capture_handshake_scapy(bssid, channel, interface, duration, output_file)` | Capture un handshake |
| `extract_hash_from_pcap(pcap_file)` | Extrait le hash du fichier PCAP |
| `check_requirements()` | Vérifie les dépendances installées |

### WiFiNetwork - Dataclass

```python
@dataclass
class WiFiNetwork:
    ssid: str                    # Nom du réseau
    bssid: str                   # MAC du point d'accès
    channel: int                 # Canal WiFi (1-14)
    encryption: str              # WPA, WPA2, WPA3, WEP, Open
    signal_strength: int         # Force du signal en dBm
    clients: List[str]           # MACs des clients connectés
    handshakes_captured: int     # Nombre de handshakes capturés
```

## 🔧 Prérequis techniques

### Matériel
- ✅ Carte WiFi compatible mode moniteur
- ✅ Drivers Linux appropriés
- ✅ Antenne externe (optionnel, améliore la capture)

### Logiciel
- ✅ Python 3.7+
- ✅ Scapy (déjà dans votre projet)
- ✅ Aircrack-ng suite
- ✅ hcxtools (optionnel mais recommandé)
- ✅ Droits ROOT/SUDO

### Vérifier la compatibilité de votre carte WiFi

```bash
# Vérifier le mode moniteur
iw list | grep "Supported interface modes" -A 10

# Doit afficher "monitor" dans la liste
```

## ⚠️ Avertissements légaux

**IMPORTANT** : L'utilisation de ce scanner est soumise à la loi.

### ✅ Utilisations AUTORISÉES :
- Tests sur VOS propres réseaux WiFi
- Audits de sécurité avec autorisation écrite
- Environnements de formation/CTF
- Recherche académique avec consentement

### ❌ Utilisations INTERDITES :
- Scanner des réseaux sans autorisation
- Capturer des handshakes de tiers
- Cracker des mots de passe sans permission
- Toute activité illégale

**La capture de handshakes WiFi sans autorisation est ILLÉGALE dans la plupart des pays et peut entraîner des poursuites judiciaires.**

## 🐛 Dépannage

### Problème : "Aucune interface WiFi détectée"
**Solution** :
```bash
iwconfig  # Vérifier les interfaces
lspci | grep -i wireless  # Vérifier la carte
```

### Problème : "Échec activation mode moniteur"
**Solution** :
```bash
sudo systemctl stop NetworkManager
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

### Problème : "Handshake non capturé"
**Solutions** :
- Augmenter la durée de capture (60s → 120s)
- Déconnecter/reconnecter un appareil au réseau
- Vérifier le canal avec `airodump-ng`
- Utiliser une antenne externe plus puissante

### Problème : "Permission denied"
**Solution** :
```bash
# Toujours exécuter avec sudo
sudo python3 script.py
```

## 📚 Ressources utiles

### Documentation
- [Aircrack-ng](https://www.aircrack-ng.org/documentation.html)
- [Scapy WiFi](https://scapy.readthedocs.io/)
- [Hashcat WPA/WPA2](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Wordlists pour cracking
- `rockyou.txt` (classique, 14M de mots de passe)
- `/usr/share/wordlists/` (Kali Linux)
- [SecLists](https://github.com/danielmiessler/SecLists)

### Outils complémentaires
- **Hashcat** : GPU cracking ultra-rapide
- **John the Ripper** : Génération de wordlists
- **Wireshark** : Analyse des captures PCAP
- **Airgeddon** : Framework tout-en-un

## 🎨 Intégration dans la GUI

Pour intégrer le scanner WiFi dans votre interface graphique `gui.py`, consultez le fichier **WIFI_INTEGRATION.md** qui contient :

- Code complet pour créer un onglet WiFi
- Gestion des événements (scan, capture, etc.)
- Interface utilisateur avec tables et boutons
- Gestion des threads pour ne pas bloquer la GUI
- Gestion des erreurs et feedback utilisateur

## 📊 Exemple de sortie

### Scan de réseaux
```
✓ 12 réseaux détectés:

SSID                      BSSID              Canal   Signal    Chiffrement
--------------------------------------------------------------------------------
MonWiFi-5G               AA:BB:CC:DD:EE:FF  36      📶🟢 -42 dBm  🔒 WPA2
MonWiFi-2.4G             AA:BB:CC:DD:EE:FE  6       📶🟢 -48 dBm  🔒 WPA2
Voisin-WiFi              11:22:33:44:55:66  11      📶🟡 -58 dBm  🔒 WPA2
FreeWiFi                 99:88:77:66:55:44  1       📶🟠 -68 dBm  🔒 WPA2
Hotspot                  12:34:56:78:90:AB  6       📶🔴 -78 dBm  🔓 Open
```

### Capture de handshake
```
[1/4] Paquet EAPOL 1/4 capturé
[2/4] Paquet EAPOL 2/4 capturé
[3/4] Paquet EAPOL 3/4 capturé
[4/4] Paquet EAPOL 4/4 capturé

✓ Handshake complet capturé pour AA:BB:CC:DD:EE:FF
✓ Handshake sauvegardé: /tmp/handshake_AABBCCDDEEFF.pcap
✓ Hash extrait: /tmp/handshake_AABBCCDDEEFF.hc22000

Commandes pour cracker:
  hashcat -m 22000 /tmp/handshake_AABBCCDDEEFF.hc22000 rockyou.txt
  aircrack-ng -w rockyou.txt /tmp/handshake_AABBCCDDEEFF.pcap
```

## 🎓 Cas d'usage éducatifs

### 1. Audit de sécurité de votre réseau
Testez la force de votre mot de passe WiFi :
```bash
sudo python3 list_wifi_networks.py  # Identifier votre réseau
sudo python3 quick_wifi_hash.py [VOTRE_BSSID] [CANAL]
hashcat -m 22000 hash.hc22000 rockyou.txt
```

### 2. Formation à la sécurité WiFi
Démontrer les vulnérabilités WPA2 :
- Capture de handshakes
- Temps de crack selon la complexité
- Importance des mots de passe forts

### 3. CTF et challenges de sécurité
Utiliser dans des compétitions de hacking éthique.

## 💡 Améliorations futures possibles

- [ ] Support WPA3 (SAE handshake)
- [ ] Attaque PMKID (plus rapide, sans client)
- [ ] Déauthentification automatique (forcer reconnexion)
- [ ] Cracking intégré avec hashcat
- [ ] Analyse de la force du signal en temps réel
- [ ] Détection des clients cachés
- [ ] Export des résultats en JSON/CSV
- [ ] Support multi-interface (plusieurs cartes WiFi)

## 🤝 Contribution

Ce module a été créé pour votre projet Scanner IP. N'hésitez pas à :
- Adapter le code à vos besoins
- Ajouter des fonctionnalités
- Améliorer l'interface utilisateur
- Intégrer dans la GUI principale

## 📞 Support

Si vous rencontrez des problèmes :
1. Vérifiez les prérequis (ROOT, aircrack-ng, carte WiFi compatible)
2. Consultez la section Dépannage
3. Lisez WIFI_INTEGRATION.md pour l'intégration GUI
4. Testez avec les scripts fournis

---

**Bon hacking (éthique) ! 🎩**

*Développé pour Scanner IP - Module WiFi v1.0*
