# Intégration du Scanner WiFi

Ce document explique comment intégrer le scanner WiFi dans votre projet Scanner IP.

## 📋 Prérequis

### 1. Droits ROOT/SUDO
Le scanner WiFi **nécessite absolument** les droits root pour :
- Mettre la carte WiFi en mode moniteur
- Capturer les paquets réseau
- Changer de canal WiFi

### 2. Dépendances système

```bash
# Installer aircrack-ng suite (REQUIS)
sudo apt-get update
sudo apt-get install aircrack-ng

# Installer hcxtools pour hashcat (OPTIONNEL mais recommandé)
sudo apt-get install hcxtools

# Vérifier l'installation
airmon-ng
airodump-ng --help
```

### 3. Dépendances Python

Scapy est déjà installé dans votre projet, mais vérifiez :

```bash
pip install scapy
```

## 🧪 Test rapide

Pour tester le scanner WiFi :

```bash
# IMPORTANT: Exécuter avec sudo
sudo python3 test_wifi_scanner.py
```

Le script de test va :
1. ✓ Vérifier les dépendances
2. ✓ Détecter les interfaces WiFi
3. ✓ Activer le mode moniteur
4. ✓ Scanner les réseaux WiFi disponibles
5. ✓ (Optionnel) Capturer un handshake
6. ✓ (Optionnel) Extraire le hash pour hashcat

## 📖 Utilisation du module

### Exemple simple

```python
from wifi_scanner import WiFiScanner

# Créer le scanner
scanner = WiFiScanner(callback=lambda msg, prog: print(f"[{prog}%] {msg}"))

# Vérifier les dépendances
requirements = scanner.check_requirements()
if not requirements['root_access']:
    print("Nécessite sudo!")
    exit(1)

# Lister les interfaces WiFi
interfaces = scanner.get_wifi_interfaces()
print(f"Interfaces: {interfaces}")

# Activer le mode moniteur
mon_interface = scanner.enable_monitor_mode('wlan0')
print(f"Mode moniteur: {mon_interface}")

# Scanner les réseaux (30 secondes)
networks = scanner.scan_networks_airodump(mon_interface, duration=30)

for network in networks:
    print(f"{network.ssid} - {network.bssid} - Canal {network.channel} - {network.encryption}")

# Capturer un handshake
success = scanner.capture_handshake_scapy(
    bssid='AA:BB:CC:DD:EE:FF',  # BSSID du réseau cible
    channel=6,                    # Canal du réseau
    interface=mon_interface,
    duration=60,                  # Capturer pendant 60s
    output_file='/tmp/handshake.pcap'
)

if success:
    # Extraire le hash
    hash_value = scanner.extract_hash_from_pcap('/tmp/handshake.pcap')
    print(f"Hash: {hash_value}")

    # Utiliser avec hashcat
    # hashcat -m 22000 hash_value.hc22000 wordlist.txt

# Désactiver le mode moniteur
scanner.disable_monitor_mode(mon_interface)
```

## 🎨 Intégration dans la GUI

Pour intégrer le scanner WiFi dans `gui.py`, suivez ces étapes :

### 1. Importer le module

```python
from wifi_scanner import WiFiScanner, WiFiNetwork
```

### 2. Ajouter un onglet WiFi

Dans la fonction `create_main_layout()` de gui.py, ajoutez un nouvel onglet :

```python
# Créer l'onglet WiFi
self.wifi_tab = ttk.Frame(self.notebook)
self.notebook.add(self.wifi_tab, text="📡 WiFi Scanner")

# Créer l'interface WiFi
self.create_wifi_scanner_interface()
```

### 3. Créer l'interface WiFi

```python
def create_wifi_scanner_interface(self):
    """Crée l'interface du scanner WiFi"""

    # Frame principal
    main_frame = ttk.Frame(self.wifi_tab, padding=10)
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Vérification ROOT
    if os.geteuid() != 0:
        warning_label = ttk.Label(
            main_frame,
            text="⚠️ Le scanner WiFi nécessite les droits ROOT/SUDO\nRelancez l'application avec: sudo python3 gui.py",
            foreground="red",
            font=("Arial", 12, "bold")
        )
        warning_label.grid(row=0, column=0, pady=20)
        return

    # Liste des interfaces WiFi
    ttk.Label(main_frame, text="Interface WiFi:").grid(row=0, column=0, sticky=tk.W, pady=5)
    self.wifi_interface_var = tk.StringVar()
    self.wifi_interface_combo = ttk.Combobox(
        main_frame,
        textvariable=self.wifi_interface_var,
        state='readonly',
        width=20
    )
    self.wifi_interface_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

    # Bouton rafraîchir interfaces
    ttk.Button(
        main_frame,
        text="🔄 Rafraîchir",
        command=self.refresh_wifi_interfaces
    ).grid(row=0, column=2, pady=5, padx=5)

    # Bouton activer mode moniteur
    self.monitor_mode_btn = ttk.Button(
        main_frame,
        text="📡 Activer Mode Moniteur",
        command=self.toggle_monitor_mode
    )
    self.monitor_mode_btn.grid(row=1, column=0, columnspan=3, pady=10)

    # Bouton scanner réseaux
    self.scan_wifi_btn = ttk.Button(
        main_frame,
        text="🔍 Scanner Réseaux WiFi",
        command=self.scan_wifi_networks,
        state='disabled'
    )
    self.scan_wifi_btn.grid(row=2, column=0, columnspan=3, pady=10)

    # Table des réseaux WiFi
    columns = ('ssid', 'bssid', 'channel', 'encryption', 'signal')
    self.wifi_tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)

    self.wifi_tree.heading('ssid', text='SSID')
    self.wifi_tree.heading('bssid', text='BSSID')
    self.wifi_tree.heading('channel', text='Canal')
    self.wifi_tree.heading('encryption', text='Chiffrement')
    self.wifi_tree.heading('signal', text='Signal (dBm)')

    self.wifi_tree.column('ssid', width=200)
    self.wifi_tree.column('bssid', width=150)
    self.wifi_tree.column('channel', width=80)
    self.wifi_tree.column('encryption', width=150)
    self.wifi_tree.column('signal', width=100)

    self.wifi_tree.grid(row=3, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Scrollbar
    scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.wifi_tree.yview)
    scrollbar.grid(row=3, column=3, sticky=(tk.N, tk.S))
    self.wifi_tree.configure(yscrollcommand=scrollbar.set)

    # Bouton capturer handshake
    self.capture_handshake_btn = ttk.Button(
        main_frame,
        text="🎯 Capturer Handshake",
        command=self.capture_selected_handshake,
        state='disabled'
    )
    self.capture_handshake_btn.grid(row=4, column=0, columnspan=3, pady=10)

    # Initialiser le scanner
    self.wifi_scanner = WiFiScanner(callback=self.update_wifi_progress)
    self.monitor_mode_active = False
    self.monitor_interface = None

    # Charger les interfaces
    self.refresh_wifi_interfaces()

def refresh_wifi_interfaces(self):
    """Rafraîchit la liste des interfaces WiFi"""
    interfaces = self.wifi_scanner.get_wifi_interfaces()
    self.wifi_interface_combo['values'] = interfaces
    if interfaces:
        self.wifi_interface_combo.current(0)

def toggle_monitor_mode(self):
    """Active/désactive le mode moniteur"""
    if not self.monitor_mode_active:
        interface = self.wifi_interface_var.get()
        if not interface:
            messagebox.showwarning("Attention", "Sélectionnez une interface WiFi")
            return

        self.monitor_interface = self.wifi_scanner.enable_monitor_mode(interface)
        if self.monitor_interface:
            self.monitor_mode_active = True
            self.monitor_mode_btn.config(text="🛑 Désactiver Mode Moniteur")
            self.scan_wifi_btn.config(state='normal')
            messagebox.showinfo("Succès", f"Mode moniteur activé: {self.monitor_interface}")
        else:
            messagebox.showerror("Erreur", "Échec activation mode moniteur")
    else:
        if self.wifi_scanner.disable_monitor_mode(self.monitor_interface):
            self.monitor_mode_active = False
            self.monitor_mode_btn.config(text="📡 Activer Mode Moniteur")
            self.scan_wifi_btn.config(state='disabled')
            self.capture_handshake_btn.config(state='disabled')
            messagebox.showinfo("Succès", "Mode moniteur désactivé")

def scan_wifi_networks(self):
    """Lance le scan des réseaux WiFi"""
    if not self.monitor_interface:
        return

    # Lancer le scan dans un thread
    def scan_thread():
        networks = self.wifi_scanner.scan_networks_airodump(self.monitor_interface, duration=30)

        # Mettre à jour l'interface (dans le thread principal)
        self.root.after(0, lambda: self.display_wifi_networks(networks))

    threading.Thread(target=scan_thread, daemon=True).start()

def display_wifi_networks(self, networks):
    """Affiche les réseaux WiFi dans la table"""
    # Vider la table
    for item in self.wifi_tree.get_children():
        self.wifi_tree.delete(item)

    # Ajouter les réseaux
    for network in sorted(networks, key=lambda x: x.signal_strength, reverse=True):
        self.wifi_tree.insert('', tk.END, values=(
            network.ssid,
            network.bssid,
            network.channel,
            network.encryption,
            network.signal_strength
        ))

    # Activer le bouton de capture
    self.capture_handshake_btn.config(state='normal')

    messagebox.showinfo("Scan terminé", f"{len(networks)} réseaux détectés")

def capture_selected_handshake(self):
    """Capture le handshake du réseau sélectionné"""
    selection = self.wifi_tree.selection()
    if not selection:
        messagebox.showwarning("Attention", "Sélectionnez un réseau")
        return

    item = self.wifi_tree.item(selection[0])
    values = item['values']
    bssid = values[1]
    channel = values[2]
    ssid = values[0]

    # Demander confirmation
    result = messagebox.askyesno(
        "Capture de handshake",
        f"Capturer le handshake pour:\n\n"
        f"SSID: {ssid}\n"
        f"BSSID: {bssid}\n"
        f"Canal: {channel}\n\n"
        f"Durée: 60 secondes\n\n"
        f"⚠️ Assurez-vous d'avoir l'autorisation pour ce réseau!"
    )

    if not result:
        return

    # Lancer la capture dans un thread
    def capture_thread():
        output_file = f"/tmp/handshake_{bssid.replace(':', '')}.pcap"

        success = self.wifi_scanner.capture_handshake_scapy(
            bssid=bssid,
            channel=int(channel),
            interface=self.monitor_interface,
            duration=60,
            output_file=output_file
        )

        # Afficher le résultat
        self.root.after(0, lambda: self.on_handshake_captured(success, output_file, ssid))

    threading.Thread(target=capture_thread, daemon=True).start()

def on_handshake_captured(self, success, pcap_file, ssid):
    """Callback après capture de handshake"""
    if success:
        # Essayer d'extraire le hash
        hash_value = self.wifi_scanner.extract_hash_from_pcap(pcap_file)

        message = f"✓ Handshake capturé avec succès!\n\n"
        message += f"Fichier PCAP: {pcap_file}\n\n"

        if hash_value:
            message += f"Hash: {hash_value}\n\n"
            message += "Commandes pour cracker:\n"
            message += f"hashcat -m 22000 {hash_value} wordlist.txt\n"
            message += f"aircrack-ng -w wordlist.txt {pcap_file}"

        messagebox.showinfo("Succès", message)
    else:
        messagebox.showwarning(
            "Échec",
            f"Handshake non capturé pour {ssid}\n\n"
            "Essayez de déconnecter/reconnecter un appareil au réseau"
        )

def update_wifi_progress(self, message, progress):
    """Callback pour les mises à jour du scanner WiFi"""
    # Mettre à jour la barre de progression ou les logs
    self.log_message(message)
```

## ⚠️ Avertissements légaux

**IMPORTANT**: L'utilisation de ce scanner WiFi est soumise à des restrictions légales :

1. ✅ **Autorisé** :
   - Tests sur vos propres réseaux WiFi
   - Audits de sécurité avec autorisation écrite
   - Environnements de formation/CTF
   - Recherche en sécurité avec consentement

2. ❌ **INTERDIT** :
   - Scanner des réseaux WiFi sans autorisation
   - Capturer des handshakes de réseaux tiers
   - Cracker des mots de passe WiFi sans permission
   - Toute activité illégale

**La capture de handshakes WiFi sans autorisation est ILLÉGALE dans la plupart des pays.**

## 🔧 Dépannage

### Problème: "Aucune interface WiFi détectée"

**Solution** :
```bash
# Vérifier que la carte WiFi est reconnue
lspci | grep -i wireless
# ou
lsusb | grep -i wireless

# Vérifier les drivers
iwconfig
```

### Problème: "Échec activation mode moniteur"

**Solutions possibles** :
```bash
# 1. Arrêter NetworkManager
sudo systemctl stop NetworkManager

# 2. Killer les processus qui interfèrent
sudo airmon-ng check kill

# 3. Vérifier que la carte supporte le mode moniteur
iw list | grep "Supported interface modes" -A 10
```

### Problème: "Permission denied"

**Solution** :
```bash
# Exécuter avec sudo
sudo python3 gui.py
# ou
sudo python3 test_wifi_scanner.py
```

### Problème: "Handshake non capturé"

**Solutions** :
- Augmenter la durée de capture (60s → 120s)
- Déconnecter/reconnecter un appareil au réseau WiFi
- Vérifier que vous êtes sur le bon canal
- Utiliser une antenne externe plus puissante

## 📚 Ressources supplémentaires

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Scapy WiFi Tutorial](https://scapy.readthedocs.io/en/latest/usage.html#sniffing)
- [Hashcat Mode 22000 (WPA/WPA2)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [hcxtools GitHub](https://github.com/ZerBea/hcxtools)

## 📝 Exemple de workflow complet

```bash
# 1. Installer les dépendances
sudo apt-get install aircrack-ng hcxtools

# 2. Tester le scanner
sudo python3 test_wifi_scanner.py

# 3. Lancer la GUI avec WiFi (à implémenter)
sudo python3 gui.py

# 4. Dans la GUI:
#    - Onglet "WiFi Scanner"
#    - Sélectionner interface (wlan0)
#    - Activer mode moniteur
#    - Scanner réseaux
#    - Sélectionner votre réseau
#    - Capturer handshake
#    - Sauvegarder le hash

# 5. Cracker le hash (sur votre réseau)
hashcat -m 22000 handshake.hc22000 rockyou.txt

# Ou avec aircrack-ng
aircrack-ng -w rockyou.txt handshake.pcap
```

## ✅ Checklist d'intégration

- [ ] Installer aircrack-ng (`sudo apt-get install aircrack-ng`)
- [ ] Installer hcxtools (optionnel)
- [ ] Tester avec `sudo python3 test_wifi_scanner.py`
- [ ] Vérifier que l'interface WiFi supporte le mode moniteur
- [ ] Ajouter l'onglet WiFi dans gui.py
- [ ] Implémenter les fonctions d'interface
- [ ] Tester la capture de handshake sur votre réseau
- [ ] Ajouter la gestion des erreurs
- [ ] Documenter pour les utilisateurs

---

**Développé pour le projet Scanner IP - Module WiFi**
