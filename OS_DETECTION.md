# 🔍 Détection Avancée des Versions d'OS

Le scanner dispose maintenant de **3 niveaux de détection d'OS**, du plus basique au plus précis.

## 📊 Niveaux de Détection

### Niveau 1: TTL (Time To Live) - Basique
**Précision**: Faible (type d'OS uniquement)
**Vitesse**: Très rapide
**Exemples**:
- TTL 64 → Linux/Unix
- TTL 128 → Windows
- TTL 255 → Cisco/Network Device

**Limitations**: Ne donne que le type, pas la version

---

### Niveau 2: Adresse MAC (OUI) - Moyen
**Précision**: Moyenne (fabricant + type d'appareil)
**Vitesse**: Rapide
**Exemples**:
- `B4:CE:F6:xx:xx:xx` → Google (Pixel) → **Android (Pixel)**
- `A4:B1:97:xx:xx:xx` → Apple (iPhone) → **iOS (iPhone)**
- `E8:50:8B:xx:xx:xx` → Samsung (Galaxy) → **Android (Samsung)**

**Avantages**:
- Détecte précisément les appareils mobiles
- 120+ fabricants reconnus
- Pas besoin de ports ouverts

**Limitations**: Ne donne pas la version exacte d'Android/iOS

---

### Niveau 3: Bannières de Services - Avancé ⭐
**Précision**: Élevée (version exacte de l'OS!)
**Vitesse**: Plus lent (nécessite connexion aux services)
**Nécessite**: Ports ouverts (SSH, HTTP, FTP, etc.)

## 🎯 Détection par Service

### SSH (Port 22) - Le Plus Précis

**Exemples de bannières**:

```
SSH-2.0-OpenSSH_9.2p1 Debian-2+deb13u1
```
→ **Debian 13** ✅

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
```
→ **Ubuntu** ✅

```
SSH-2.0-OpenSSH_for_Windows_8.1
```
→ **Windows Server** ✅

```
SSH-2.0-OpenSSH_8.4 FreeBSD-20210907
```
→ **FreeBSD** ✅

---

### HTTP (Ports 80, 443, 8080) - Très Utile

**Exemples de bannières**:

```
Server: Apache/2.4.57 (Debian)
```
→ **Debian** ✅

```
Server: nginx/1.18.0 (Ubuntu)
```
→ **Ubuntu** ✅

```
Server: Microsoft-IIS/10.0
```
→ **Windows Server 2016+** ✅

```
Server: Apache/2.4.6 (CentOS)
```
→ **CentOS** ✅

---

### FTP (Port 21) - Complémentaire

**Exemples**:

```
220 ProFTPD 1.3.6 Server (Debian)
```
→ **Debian** ✅

```
220 Microsoft FTP Service
```
→ **Windows Server** ✅

---

### SMB (Port 445) - Windows

**Détecte**:
- Windows 7, 8, 10, 11
- Windows Server 2012, 2016, 2019
- Samba (Linux)

## 🔄 Ordre de Priorité

Le scanner utilise la détection **dans cet ordre** (de la plus précise à la moins précise):

1. **Bannières de services** (si ports ouverts)
2. **Adresse MAC** (si disponible)
3. **TTL** (fallback)

### Exemple de Détection Complète

**Scan d'un serveur Debian 13:**

```
Étape 1: Ping
  TTL: 64 → Linux/Unix (basique)

Étape 2: Adresse MAC
  MAC: XX:XX:XX:... → Pas dans la base → Pas de détection

Étape 3: Ports Ouverts
  Port 22: OPEN (SSH)
  Port 80: OPEN (HTTP)

Étape 4: Bannières
  Port 22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb13u1"
  → Analyse → Debian 13 ✅

Résultat Final: Debian 13
```

## 📱 Cas Particuliers

### Smartphones Android

**Problème**: Les smartphones ont rarement des ports ouverts

**Solution**: Détection via MAC address

```
MAC: B4:CE:F6:xx:xx:xx (Google Pixel)
→ Android (Pixel) ✅
```

**Limitation**: Pas la version exacte d'Android (car pas de services exposés)

---

### Serveurs Linux avec SSH

**Meilleur cas**: SSH ouvert

```
Port 22: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb13u1
→ Debian 13 ✅ (version exacte!)
```

---

### Machines Windows

**Options**:

1. **HTTP/IIS ouvert**:
   ```
   Server: Microsoft-IIS/10.0
   → Windows Server 2016+ ✅
   ```

2. **SMB ouvert** (port 445):
   ```
   Détection via SMB
   → Windows 10/11 ✅
   ```

3. **Sinon**:
   ```
   TTL: 128
   → Windows (type uniquement)
   ```

## ⚙️ Configuration

### Activer la Détection Avancée

Dans l'interface graphique, choisissez:

- **Scan Normal** → Détection MAC + TTL
- **Scan Approfondi** → Détection MAC + TTL + **Bannières** ⭐

### Scan Personnalisé

Cochez:
- ✅ **Détection services** → Active la collecte de bannières

## 🎯 Ports Scannés pour Détection

Par priorité (les 5 premiers ports ouverts):

1. **Port 22** (SSH) - Priorité max
2. **Port 80** (HTTP) - Haute
3. **Port 443** (HTTPS) - Haute
4. **Port 21** (FTP) - Moyenne
5. **Port 445** (SMB) - Moyenne
6. Autres ports ouverts

## 📈 Performance

### Impact sur la Vitesse

| Type de Scan | Durée /24 | Détection OS |
|--------------|-----------|--------------|
| Quick | ~30s | TTL uniquement |
| Normal | ~2min | TTL + MAC |
| Deep | ~10min | TTL + MAC + **Bannières** |

### Optimisations

- Limite à **5 ports max** par hôte pour bannières
- Timeout de **2s** par bannière
- Priorité aux ports importants (SSH, HTTP)
- Parallélisation du scan

## 🔍 Exemples de Résultats

### Réseau Domestique Typique

```
192.168.1.1   → Router      → Router/Network Device
192.168.1.10  → Pixel       → Android (Pixel)
192.168.1.20  → iPhone      → iOS (iPhone)
192.168.1.50  → Serveur     → Debian 13 (via SSH)
192.168.1.100 → PC          → Windows 10/11 (via SMB)
192.168.1.150 → NAS         → Linux (Samba)
```

### Réseau Entreprise

```
10.0.0.1    → Firewall     → Cisco/Network Device
10.0.0.10   → Web Server   → Ubuntu 22.04 (via HTTP)
10.0.0.20   → DB Server    → Debian 13 (via SSH)
10.0.0.30   → File Server  → Windows Server 2019 (via SMB)
10.0.0.100  → Workstation  → Windows 10 (via TTL)
```

## 💡 Conseils

### Pour Meilleure Détection

1. ✅ **Utilisez sudo** → Scan ARP pour MAC
2. ✅ **Scan Deep** → Active bannières
3. ✅ **Ports communs ouverts** → SSH, HTTP
4. ✅ **Réseau local** → Meilleur accès

### Limitations

⚠️ **Pare-feu** → Peut bloquer bannières
⚠️ **Services désactivés** → Pas de détection avancée
⚠️ **Smartphones** → Rarement des ports ouverts
⚠️ **Stealth mode** → Certains serveurs cachent leur OS

## 🚀 Utilisation

```bash
# Lancer un scan approfondi
sudo python3 main.py

# Choisir "Deep" dans l'interface
# ✅ Cocher "Détection services"
# ✅ Lancer le scan

# Résultat: Versions exactes d'OS! 🎉
```

---

**Votre scanner détecte maintenant les versions exactes comme Debian 13, Ubuntu 22.04, Windows Server 2019, etc.!** ✨
