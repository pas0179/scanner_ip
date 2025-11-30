"""
Interface graphique principale du Scanner IP - Design moderne avec ttkbootstrap
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from datetime import datetime
import json
import logging
from pathlib import Path
import threading
import os

from config import (
    WINDOW_TITLE, WINDOW_SIZE, THEME_COLOR, ACCENT_COLOR,
    SUCCESS_COLOR, ERROR_COLOR, COMMON_PORTS,
    EXTENDED_PORTS, EXPORT_FORMATS, HISTORY_DIR, SCAN_TYPES
)
from utils import (
    get_network_range, get_local_ip, validate_network,
    export_data, parse_port_range, format_scan_duration, is_root
)
from scan_thread import ScanThread
from scanner import IPScanner

# Import WiFi scanner
try:
    from wifi_scanner import WiFiScanner, WiFiNetwork
    WIFI_AVAILABLE = True
except ImportError:
    WIFI_AVAILABLE = False
    print("⚠️ Module wifi_scanner non disponible")

logger = logging.getLogger(__name__)


class MainWindow:
    """
    Fenêtre principale de l'application
    """

    def __init__(self, root):
        """
        Initialise la fenêtre principale avec design moderne

        Args:
            root: Instance ttkbootstrap root
        """
        self.root = root
        self.root.title("🔍 " + WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)

        # Variables Scanner IP
        self.scan_thread = None
        self.current_results = []
        self.scan_start_time = None
        self.has_root = is_root()

        # Historique
        self.history_file = HISTORY_DIR / "scan_history.json"
        self.scan_history = self._load_history()

        # Variables Scanner WiFi
        self.wifi_scanner = None
        self.wifi_monitor_mode_active = False
        self.wifi_monitor_interface = None
        self.wifi_networks = []
        self.wifi_scan_thread = None

        # Initialiser le scanner WiFi si disponible et root
        if WIFI_AVAILABLE and self.has_root:
            try:
                self.wifi_scanner = WiFiScanner(callback=self._update_wifi_progress)
            except Exception as e:
                logger.error(f"Erreur initialisation WiFi scanner: {e}")
                self.wifi_scanner = None

        # Configuration de la fenêtre
        self._create_widgets()
        self._check_root_privileges()

    def _create_widgets(self):
        """
        Crée tous les widgets avec design moderne ttkbootstrap et onglets
        """
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.grid(row=0, column=0, sticky=(W, E, N, S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # En-tête moderne avec carte
        header_frame = ttk.Frame(main_frame, bootstyle="dark")
        header_frame.grid(row=0, column=0, pady=(0, 20), sticky=(W, E), ipady=15, ipadx=15)
        header_frame.columnconfigure(0, weight=1)

        # Titre avec icône
        title_label = ttk.Label(
            header_frame,
            text="🔍 Scanner IP & WiFi",
            font=("Segoe UI", 24, "bold"),
            bootstyle="inverse-dark"
        )
        title_label.grid(row=0, column=0, sticky=W, padx=10)

        # Sous-titre
        from utils import get_local_ip
        subtitle = f"Analyse réseau avancée • Votre IP: {get_local_ip()}"
        subtitle_label = ttk.Label(
            header_frame,
            text=subtitle,
            font=("Segoe UI", 11),
            bootstyle="inverse-secondary"
        )
        subtitle_label.grid(row=1, column=0, sticky=W, padx=10, pady=(5, 0))

        # Créer le Notebook (système d'onglets)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(W, E, N, S))

        # Onglet 1: Scanner IP
        self._create_scanner_ip_tab()

        # Onglet 2: Scanner WiFi
        self._create_wifi_scanner_tab()

    def _create_config_frame(self, parent):
        """
        Crée le frame de configuration du scan
        """
        config_frame = ttk.Labelframe(parent, text="Configuration du Scan", padding="10")
        config_frame.grid(row=1, column=0, pady=5, sticky=(W, E))
        config_frame.columnconfigure(1, weight=1)

        # Plage réseau
        ttk.Label(config_frame, text="Plage réseau:").grid(row=0, column=0, sticky=W, padx=(0, 5))
        self.network_var = tk.StringVar(value=get_network_range())
        network_entry = ttk.Entry(config_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=1, sticky=(W, E), padx=5)

        ttk.Button(config_frame, text="Détecter", command=self._auto_detect_network).grid(
            row=0, column=2, padx=5
        )

        # Type de scan
        ttk.Label(config_frame, text="Type de scan:").grid(row=1, column=0, sticky=W, padx=(0, 5), pady=5)
        self.scan_type_var = tk.StringVar(value="normal")
        scan_types = ["quick", "normal", "deep", "custom"]
        scan_type_combo = ttk.Combobox(
            config_frame,
            textvariable=self.scan_type_var,
            values=scan_types,
            state="readonly",
            width=28
        )
        scan_type_combo.grid(row=1, column=1, sticky=(W, E), padx=5, pady=5)
        scan_type_combo.bind('<<ComboboxSelected>>', self._on_scan_type_changed)

        # Frame de configuration personnalisée
        self.custom_frame = ttk.Frame(config_frame)
        self.custom_frame.grid(row=2, column=0, columnspan=3, sticky=(W, E), pady=5)
        self.custom_frame.columnconfigure(1, weight=1)

        # Ports personnalisés
        ttk.Label(self.custom_frame, text="Ports:").grid(row=0, column=0, sticky=W)
        self.custom_ports_var = tk.StringVar(value="")
        custom_ports_entry = ttk.Entry(self.custom_frame, textvariable=self.custom_ports_var)
        custom_ports_entry.grid(row=0, column=1, sticky=(W, E), padx=5)
        ttk.Label(self.custom_frame, text="(ex: 80,443,8000-8100)", font=('Arial', 8)).grid(
            row=0, column=2, sticky=W
        )

        # Options
        self.option_os_var = tk.BooleanVar(value=False)
        self.option_service_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            self.custom_frame,
            text="Détection OS",
            variable=self.option_os_var
        ).grid(row=1, column=0, sticky=W, pady=5)

        ttk.Checkbutton(
            self.custom_frame,
            text="Détection services",
            variable=self.option_service_var
        ).grid(row=1, column=1, sticky=W, pady=5)

        # Cacher le frame custom par défaut
        self.custom_frame.grid_remove()

    def _create_control_frame(self, parent):
        """
        Crée le frame de contrôle avec boutons modernes Bootstrap
        """
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=2, column=0, pady=20, sticky=(W, E))

        # Première ligne de boutons (actions principales)
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=X, pady=5)

        # Bouton Démarrer (vert, grand)
        self.btn_scan = ttk.Button(
            row1,
            text="▶  Démarrer le Scan",
            command=self._start_scan,
            bootstyle="success",
            width=20
        )
        self.btn_scan.pack(side=LEFT, padx=5)

        # Bouton Arrêter (rouge)
        self.btn_stop = ttk.Button(
            row1,
            text="⏹  Arrêter",
            command=self._stop_scan,
            state=DISABLED,
            bootstyle="danger",
            width=15
        )
        self.btn_stop.pack(side=LEFT, padx=5)

        # Bouton Scan Vulnérabilités (orange)
        self.btn_vuln_scan = ttk.Button(
            row1,
            text="🔒  Scan Vulnérabilités",
            command=self._scan_vulnerabilities,
            bootstyle="warning",
            width=20
        )
        self.btn_vuln_scan.pack(side=LEFT, padx=5)

        # Séparateur visuel
        ttk.Separator(row1, orient=VERTICAL).pack(side=LEFT, fill=Y, padx=10)

        # Bouton Exporter (bleu)
        ttk.Button(
            row1,
            text="💾  Exporter",
            command=self._export_results,
            bootstyle="info",
            width=15
        ).pack(side=LEFT, padx=5)

        # Bouton Effacer
        ttk.Button(
            row1,
            text="🗑  Effacer",
            command=self._clear_results,
            bootstyle="secondary-outline",
            width=12
        ).pack(side=LEFT, padx=5)

        # Bouton Historique
        ttk.Button(
            row1,
            text="📜  Historique",
            command=self._show_history,
            bootstyle="secondary-outline",
            width=14
        ).pack(side=LEFT, padx=5)

        # Deuxième ligne de boutons (paramètres et quitter)
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=X, pady=5)

        # BOUTON THÈMES (à gauche)
        ttk.Button(
            row2,
            text="🎨  Thèmes",
            command=self._show_theme_selector,
            bootstyle="info-outline",
            width=15
        ).pack(side=LEFT, padx=5)

        # BOUTON QUITTER (à droite)
        ttk.Button(
            row2,
            text="✖  Quitter",
            command=self._quit_application,
            bootstyle="danger-outline",
            width=15
        ).pack(side=RIGHT, padx=5)

        # Alerte privilèges si pas root
        if not self.has_root:
            alert = ttk.Label(
                parent,
                text="⚠  Exécutez avec sudo pour activer toutes les fonctionnalités avancées (scan ARP, SYN, etc.)",
                bootstyle="warning",
                font=("Segoe UI", 10),
                padding=10
            )
            alert.grid(row=3, column=0, pady=(0, 10), sticky=(W, E))

    def _create_results_frame(self, parent):
        """
        Crée le frame des résultats
        """
        results_frame = ttk.Labelframe(parent, text="Résultats", padding="10")
        results_frame.grid(row=3, column=0, pady=5, sticky=(W, E, N, S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Treeview
        columns = ('IP', 'Hostname', 'MAC', 'OS', 'Temps (ms)', 'Ports', 'Vulnérabilités')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=15)

        # Définir les colonnes
        self.tree.column('#0', width=50, stretch=False)
        self.tree.heading('#0', text='#')

        column_widths = {'IP': 120, 'Hostname': 200, 'MAC': 150, 'OS': 120, 'Temps (ms)': 70, 'Ports': 200, 'Vulnérabilités': 200}

        for col in columns:
            self.tree.column(col, width=column_widths[col])
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_treeview(c))

        # Scrollbars
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid
        self.tree.grid(row=0, column=0, sticky=(W, E, N, S))
        vsb.grid(row=0, column=1, sticky=(N, S))
        hsb.grid(row=1, column=0, sticky=(W, E))

        # Menu contextuel
        self.tree_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_menu.add_command(label="Copier IP", command=self._copy_ip)
        self.tree_menu.add_command(label="Copier MAC", command=self._copy_mac)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="Détails", command=self._show_details)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="🔍 Scan approfondi...", command=self._deep_scan_host)

        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Double-1>", lambda e: self._show_details())

    def _create_status_frame(self, parent):
        """
        Crée le frame de statut
        """
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=4, column=0, pady=(10, 0), sticky=(W, E))
        status_frame.columnconfigure(0, weight=1)

        # Barre de progression
        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.grid(row=0, column=0, sticky=(W, E), pady=(0, 5))

        # Label de statut
        self.status_var = tk.StringVar(value="Prêt")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.grid(row=1, column=0, sticky=W)

        # Compteur de résultats
        self.count_var = tk.StringVar(value="Hôtes trouvés: 0")
        count_label = ttk.Label(status_frame, textvariable=self.count_var)
        count_label.grid(row=1, column=0, sticky=E)

    def _create_scanner_ip_tab(self):
        """
        Crée l'onglet Scanner IP avec le contenu existant
        """
        # Créer le frame de l'onglet
        ip_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(ip_tab, text="🌐 Scanner IP")

        # Configurer le grid
        ip_tab.columnconfigure(0, weight=1)
        ip_tab.rowconfigure(2, weight=1)

        # Frame de configuration
        self._create_config_frame(ip_tab)

        # Frame de contrôle
        self._create_control_frame(ip_tab)

        # Frame de résultats
        self._create_results_frame(ip_tab)

        # Frame de statut
        self._create_status_frame(ip_tab)

    def _create_wifi_scanner_tab(self):
        """
        Crée l'onglet Scanner WiFi
        """
        # Créer le frame de l'onglet
        wifi_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(wifi_tab, text="📡 Scanner WiFi")

        # Configurer le grid
        wifi_tab.columnconfigure(0, weight=1)
        wifi_tab.rowconfigure(2, weight=1)

        # Vérifier si WiFi est disponible et si on a ROOT
        if not WIFI_AVAILABLE:
            warning_frame = ttk.Frame(wifi_tab)
            warning_frame.grid(row=0, column=0, sticky=(W, E, N, S), pady=50)

            ttk.Label(
                warning_frame,
                text="⚠️ Module WiFi Scanner non disponible",
                font=("Segoe UI", 16, "bold"),
                bootstyle="warning"
            ).pack(pady=10)

            ttk.Label(
                warning_frame,
                text="Le module wifi_scanner.py n'est pas accessible.\n"
                     "Vérifiez que le fichier existe dans le répertoire du projet.",
                font=("Segoe UI", 11)
            ).pack(pady=10)
            return

        if not self.has_root:
            warning_frame = ttk.Frame(wifi_tab)
            warning_frame.grid(row=0, column=0, sticky=(W, E, N, S), pady=50)

            ttk.Label(
                warning_frame,
                text="⚠️ Privilèges ROOT/SUDO requis",
                font=("Segoe UI", 16, "bold"),
                bootstyle="danger"
            ).pack(pady=10)

            ttk.Label(
                warning_frame,
                text="Le scanner WiFi nécessite les droits root pour:\n"
                     "• Activer le mode moniteur\n"
                     "• Capturer les paquets WiFi\n"
                     "• Changer de canal\n\n"
                     "Relancez l'application avec:\n"
                     "sudo python3 main.py",
                font=("Segoe UI", 11),
                justify=CENTER
            ).pack(pady=10)

            ttk.Button(
                warning_frame,
                text="📖 Instructions d'installation",
                command=self._show_wifi_instructions,
                bootstyle="info"
            ).pack(pady=20)
            return

        # Si tout est OK, créer l'interface WiFi
        self._create_wifi_interface(wifi_tab)

    def _create_wifi_interface(self, parent):
        """
        Crée l'interface complète du scanner WiFi
        """
        # Frame de configuration WiFi
        config_frame = ttk.Labelframe(parent, text="Configuration WiFi", padding="10")
        config_frame.grid(row=0, column=0, pady=5, sticky=(W, E))
        config_frame.columnconfigure(1, weight=1)

        # Sélection de l'interface WiFi
        ttk.Label(config_frame, text="Interface WiFi:").grid(row=0, column=0, sticky=W, padx=(0, 5))

        self.wifi_interface_var = tk.StringVar()
        self.wifi_interface_combo = ttk.Combobox(
            config_frame,
            textvariable=self.wifi_interface_var,
            state='readonly',
            width=20
        )
        self.wifi_interface_combo.grid(row=0, column=1, sticky=W, padx=5)

        ttk.Button(
            config_frame,
            text="🔄 Rafraîchir",
            command=self._refresh_wifi_interfaces,
            bootstyle="secondary-outline",
            width=12
        ).grid(row=0, column=2, padx=5)

        # Statut du mode moniteur
        self.wifi_monitor_status_var = tk.StringVar(value="Mode moniteur: Inactif")
        ttk.Label(
            config_frame,
            textvariable=self.wifi_monitor_status_var,
            font=("Segoe UI", 10, "bold")
        ).grid(row=1, column=0, columnspan=3, sticky=W, pady=(10, 5))

        # Frame de contrôle WiFi
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=1, column=0, pady=15, sticky=(W, E))

        # Première ligne de boutons
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=X, pady=5)

        self.btn_monitor_mode = ttk.Button(
            row1,
            text="📡 Activer Mode Moniteur",
            command=self._toggle_monitor_mode,
            bootstyle="success",
            width=25
        )
        self.btn_monitor_mode.pack(side=LEFT, padx=5)

        self.btn_scan_wifi = ttk.Button(
            row1,
            text="🔍 Scanner Réseaux WiFi",
            command=self._scan_wifi_networks,
            state=DISABLED,
            bootstyle="primary",
            width=25
        )
        self.btn_scan_wifi.pack(side=LEFT, padx=5)

        self.btn_capture_handshake = ttk.Button(
            row1,
            text="🎯 Capturer Handshake",
            command=self._capture_selected_handshake,
            state=DISABLED,
            bootstyle="warning",
            width=25
        )
        self.btn_capture_handshake.pack(side=LEFT, padx=5)

        # Deuxième ligne de boutons
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=X, pady=5)

        ttk.Button(
            row2,
            text="📖 Instructions",
            command=self._show_wifi_instructions,
            bootstyle="info-outline",
            width=18
        ).pack(side=LEFT, padx=5)

        ttk.Button(
            row2,
            text="🗑 Effacer",
            command=self._clear_wifi_results,
            bootstyle="secondary-outline",
            width=15
        ).pack(side=LEFT, padx=5)

        # Frame de résultats WiFi
        results_frame = ttk.Labelframe(parent, text="Réseaux WiFi Détectés", padding="10")
        results_frame.grid(row=2, column=0, pady=5, sticky=(W, E, N, S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Treeview pour les réseaux WiFi
        columns = ('SSID', 'BSSID', 'Canal', 'Chiffrement', 'Signal (dBm)', 'Clients')
        self.wifi_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=12)

        # Définir les colonnes
        self.wifi_tree.column('#0', width=40, stretch=False)
        self.wifi_tree.heading('#0', text='#')

        column_widths = {
            'SSID': 200,
            'BSSID': 150,
            'Canal': 80,
            'Chiffrement': 150,
            'Signal (dBm)': 120,
            'Clients': 100
        }

        for col in columns:
            self.wifi_tree.column(col, width=column_widths[col])
            self.wifi_tree.heading(col, text=col)

        # Scrollbars
        wifi_vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.wifi_tree.yview)
        wifi_hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.wifi_tree.xview)
        self.wifi_tree.configure(yscrollcommand=wifi_vsb.set, xscrollcommand=wifi_hsb.set)

        # Grid
        self.wifi_tree.grid(row=0, column=0, sticky=(W, E, N, S))
        wifi_vsb.grid(row=0, column=1, sticky=(N, S))
        wifi_hsb.grid(row=1, column=0, sticky=(W, E))

        # Menu contextuel
        self.wifi_tree_menu = tk.Menu(self.wifi_tree, tearoff=0)
        self.wifi_tree_menu.add_command(label="Copier SSID", command=self._copy_wifi_ssid)
        self.wifi_tree_menu.add_command(label="Copier BSSID", command=self._copy_wifi_bssid)
        self.wifi_tree_menu.add_separator()
        self.wifi_tree_menu.add_command(label="🎯 Capturer Handshake", command=self._capture_selected_handshake)

        self.wifi_tree.bind("<Button-3>", self._show_wifi_context_menu)
        self.wifi_tree.bind("<Double-1>", lambda e: self._capture_selected_handshake())

        # Frame de statut WiFi
        wifi_status_frame = ttk.Frame(parent)
        wifi_status_frame.grid(row=3, column=0, pady=(10, 0), sticky=(W, E))
        wifi_status_frame.columnconfigure(0, weight=1)

        # Barre de progression WiFi
        self.wifi_progress = ttk.Progressbar(wifi_status_frame, mode='determinate')
        self.wifi_progress.grid(row=0, column=0, sticky=(W, E), pady=(0, 5))

        # Label de statut WiFi
        self.wifi_status_var = tk.StringVar(value="Prêt - Sélectionnez une interface WiFi")
        wifi_status_label = ttk.Label(wifi_status_frame, textvariable=self.wifi_status_var)
        wifi_status_label.grid(row=1, column=0, sticky=W)

        # Compteur de réseaux
        self.wifi_count_var = tk.StringVar(value="Réseaux trouvés: 0")
        wifi_count_label = ttk.Label(wifi_status_frame, textvariable=self.wifi_count_var)
        wifi_count_label.grid(row=1, column=0, sticky=E)

        # Charger les interfaces au démarrage
        self._refresh_wifi_interfaces()

    def _check_root_privileges(self):
        """
        Vérifie et affiche un avertissement si pas de privilèges root
        """
        if not self.has_root:
            messagebox.showwarning(
                "Privilèges insuffisants",
                "L'application fonctionne sans privilèges root.\n\n"
                "Certaines fonctionnalités avancées seront limitées:\n"
                "- Scan ARP pour adresses MAC\n"
                "- Scan SYN pour ports\n"
                "- Détection OS avancée\n"
                "- Scanner WiFi (mode moniteur)\n\n"
                "Pour activer toutes les fonctionnalités, relancez avec:\n"
                "sudo python3 main.py"
            )

    def _auto_detect_network(self):
        """
        Détecte automatiquement la plage réseau
        """
        network = get_network_range()
        self.network_var.set(network)
        self.status_var.set(f"Réseau détecté: {network}")

    def _on_scan_type_changed(self, event=None):
        """
        Gère le changement de type de scan
        """
        scan_type = self.scan_type_var.get()

        if scan_type == "custom":
            self.custom_frame.grid()
        else:
            self.custom_frame.grid_remove()

    def _get_scan_config(self):
        """
        Récupère la configuration de scan selon le type sélectionné

        Returns:
            Dictionnaire de configuration
        """
        scan_type = self.scan_type_var.get()

        if scan_type == "custom":
            # Configuration personnalisée
            port_str = self.custom_ports_var.get().strip()
            if port_str:
                try:
                    ports = parse_port_range(port_str)
                except:
                    messagebox.showerror("Erreur", "Format de ports invalide")
                    return None
            else:
                ports = COMMON_PORTS

            return {
                'ping': True,
                'ports': True if port_str else False,
                'port_list': ports,
                'mac_address': True,
                'os_detection': self.option_os_var.get(),
                'service_detection': self.option_service_var.get(),
                'timeout': 1.0,
                'use_scapy': self.has_root
            }
        else:
            # Configuration prédéfinie
            scanner = IPScanner()
            if scan_type == "quick":
                return scanner.get_quick_scan_config()
            elif scan_type == "normal":
                return scanner.get_normal_scan_config()
            elif scan_type == "deep":
                return scanner.get_deep_scan_config()

        return None

    def _start_scan(self):
        """
        Démarre le scan
        """
        network = self.network_var.get().strip()

        if not validate_network(network):
            messagebox.showerror("Erreur", "Plage réseau invalide")
            return

        scan_config = self._get_scan_config()
        if not scan_config:
            return

        # Désactiver les boutons
        self.btn_scan.config(state=DISABLED)
        self.btn_stop.config(state=NORMAL)

        # Effacer les résultats précédents
        self._clear_results()

        # Démarrer le scan
        self.scan_start_time = datetime.now()
        self.status_var.set("Scan en cours...")
        self.progress['value'] = 0

        self.scan_thread = ScanThread(
            network=network,
            scan_config=scan_config,
            result_callback=self._on_scan_complete,
            progress_callback=self._on_scan_progress
        )
        self.scan_thread.start()

    def _stop_scan(self):
        """
        Arrête le scan en cours
        """
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.cancel()
            self.status_var.set("Arrêt du scan...")
            self.btn_stop.config(state=DISABLED)

    def _on_scan_progress(self, message: str, progress: int):
        """
        Callback de progression du scan

        Args:
            message: Message de progression
            progress: Pourcentage (0-100)
        """
        self.root.after(0, self._update_progress, message, progress)

    def _update_progress(self, message: str, progress: int):
        """
        Met à jour la progression dans l'interface

        Args:
            message: Message de progression
            progress: Pourcentage (0-100)
        """
        self.status_var.set(message)
        if progress >= 0:
            self.progress['value'] = progress

    def _on_scan_complete(self, results):
        """
        Callback appelé quand le scan est terminé

        Args:
            results: Liste des résultats
        """
        self.root.after(0, self._display_results, results)

    def _display_results(self, results):
        """
        Affiche les résultats dans le treeview

        Args:
            results: Liste des résultats
        """
        self.current_results = results

        # Effacer le treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Ajouter les résultats
        for idx, result in enumerate(results, 1):
            response_time = f"{result['response_time']:.0f}" if result['response_time'] else "N/A"
            vulnerabilities = result.get('vulnerabilities_summary', 'Non scanné')

            self.tree.insert(
                '',
                'end',
                text=str(idx),
                values=(
                    result['ip'],
                    result['hostname'],
                    result['mac'],
                    result.get('os', 'Unknown'),
                    response_time,
                    result.get('ports_summary', ''),
                    vulnerabilities
                )
            )

        # Mettre à jour le statut
        scan_duration = (datetime.now() - self.scan_start_time).total_seconds()
        self.status_var.set(
            f"Scan terminé en {format_scan_duration(scan_duration)} - "
            f"{len(results)} hôte(s) trouvé(s)"
        )
        self.count_var.set(f"Hôtes trouvés: {len(results)}")
        self.progress['value'] = 100

        # Réactiver les boutons
        self.btn_scan.config(state=NORMAL)
        self.btn_stop.config(state=DISABLED)

        # Sauvegarder dans l'historique
        self._save_to_history(results, scan_duration)

    def _clear_results(self):
        """
        Efface les résultats
        """
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.current_results = []
        self.count_var.set("Hôtes trouvés: 0")

    def _export_results(self):
        """
        Exporte les résultats
        """
        if not self.current_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return

        # Dialogue de sélection du format
        export_window = tk.Toplevel(self.root)
        export_window.title("Exporter les résultats")
        export_window.geometry("300x150")
        export_window.transient(self.root)
        export_window.grab_set()

        ttk.Label(export_window, text="Format d'export:").pack(pady=10)

        format_var = tk.StringVar(value="csv")
        for fmt in EXPORT_FORMATS:
            ttk.Radiobutton(
                export_window,
                text=fmt.upper(),
                variable=format_var,
                value=fmt
            ).pack(anchor=W, padx=50)

        def do_export():
            fmt = format_var.get()
            try:
                # Préparer les données
                export_data_list = []
                for result in self.current_results:
                    data = {
                        'IP': result['ip'],
                        'Hostname': result['hostname'],
                        'MAC': result['mac'],
                        'OS': result.get('os', 'Unknown'),
                        'Response Time (ms)': result.get('response_time', 'N/A'),
                        'Status': result['status'],
                        'Ports': result.get('ports_summary', '')
                    }
                    export_data_list.append(data)

                filepath = export_data(export_data_list, fmt)
                messagebox.showinfo("Succès", f"Résultats exportés:\n{filepath}")
                export_window.destroy()

            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export: {e}")

        ttk.Button(export_window, text="Exporter", command=do_export).pack(pady=10)

    def _sort_treeview(self, col):
        """
        Trie le treeview par colonne

        Args:
            col: Colonne à trier
        """
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]

        try:
            # Essayer de trier numériquement
            items.sort(key=lambda x: float(x[0]) if x[0] != 'N/A' else -1)
        except ValueError:
            # Sinon trier alphabétiquement
            items.sort(key=lambda x: x[0].lower())

        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)

    def _show_context_menu(self, event):
        """
        Affiche le menu contextuel
        """
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def _copy_ip(self):
        """
        Copie l'IP sélectionnée dans le presse-papier
        """
        selection = self.tree.selection()
        if selection:
            ip = self.tree.item(selection[0])['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status_var.set(f"IP copiée: {ip}")

    def _copy_mac(self):
        """
        Copie la MAC sélectionnée dans le presse-papier
        """
        selection = self.tree.selection()
        if selection:
            mac = self.tree.item(selection[0])['values'][2]
            self.root.clipboard_clear()
            self.root.clipboard_append(mac)
            self.status_var.set(f"MAC copiée: {mac}")

    def _show_details(self):
        """
        Affiche les détails d'un hôte
        """
        selection = self.tree.selection()
        if not selection:
            return

        item_values = self.tree.item(selection[0])['values']
        ip = item_values[0]

        # Trouver le résultat complet
        result = next((r for r in self.current_results if r['ip'] == ip), None)
        if not result:
            return

        # Fenêtre de détails moderne
        details_window = tk.Toplevel(self.root)
        details_window.title(f"🔍 Détails - {ip}")
        details_window.geometry("900x700")
        details_window.transient(self.root)
        details_window.configure(bg='#f0f0f0')

        # Frame principal avec scrollbar
        main_frame = ttk.Frame(details_window)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Canvas avec scrollbar
        canvas = tk.Canvas(main_frame, bg='#f0f0f0', highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor=NW)
        canvas.configure(yscrollcommand=scrollbar.set)

        # --- CARTE INFORMATIONS HÔTE ---
        info_frame = ttk.Labelframe(scrollable_frame, text="📋 Informations de l'hôte", padding=15)
        info_frame.pack(fill=X, padx=5, pady=5)

        info_data = [
            ("Adresse IP:", result['ip'], "info"),
            ("Nom d'hôte:", result['hostname'], "secondary"),
            ("Adresse MAC:", result['mac'], "secondary"),
            ("Système:", result.get('os', 'Unknown'), "warning"),
            ("Statut:", result['status'].upper(), "success" if result['status'] == 'online' else "danger"),
            ("Temps de réponse:", f"{result.get('response_time', 0):.0f} ms" if result.get('response_time') else 'N/A', "secondary")
        ]

        for idx, (label, value, style) in enumerate(info_data):
            row = ttk.Frame(info_frame)
            row.pack(fill=X, pady=2)
            ttk.Label(row, text=label, font=('Segoe UI', 10, 'bold'), width=18).pack(side=LEFT)
            ttk.Label(row, text=value, font=('Segoe UI', 10), bootstyle=style).pack(side=LEFT, padx=10)

        # --- CARTE PORTS OUVERTS ---
        if result.get('open_ports'):
            ports_frame = ttk.Labelframe(scrollable_frame, text=f"🔌 Ports ouverts ({len(result['open_ports'])})", padding=15)
            ports_frame.pack(fill=X, padx=5, pady=5)

            for port_info in result['open_ports'][:10]:  # Limiter à 10 pour l'affichage
                port_card = ttk.Frame(ports_frame, bootstyle="light")
                port_card.pack(fill=X, pady=3)

                # En-tête du port
                port_header = ttk.Frame(port_card)
                port_header.pack(fill=X, padx=5, pady=2)

                ttk.Label(
                    port_header,
                    text=f"Port {port_info['port']}",
                    font=('Segoe UI', 10, 'bold'),
                    bootstyle="info"
                ).pack(side=LEFT)

                ttk.Label(
                    port_header,
                    text=f"• {port_info['service']}",
                    font=('Segoe UI', 9)
                ).pack(side=LEFT, padx=10)

                ttk.Label(
                    port_header,
                    text=f"[{port_info['status']}]",
                    font=('Segoe UI', 9),
                    bootstyle="success"
                ).pack(side=LEFT)

                # Banner si disponible
                if port_info.get('banner'):
                    banner_text = port_info['banner'][:150]
                    ttk.Label(
                        port_card,
                        text=f"  📝 {banner_text}",
                        font=('Courier', 8),
                        foreground='gray'
                    ).pack(fill=X, padx=5)

        # --- CARTE VULNÉRABILITÉS ---
        if result.get('vulnerabilities'):
            vulnerabilities = result['vulnerabilities']

            # Compter par criticité
            critical = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITIQUE')
            high = sum(1 for v in vulnerabilities if v.get('severity') == 'ÉLEVÉ')
            medium = sum(1 for v in vulnerabilities if v.get('severity') == 'MOYEN')

            vuln_title = f"🔒 Vulnérabilités détectées ({len(vulnerabilities)}) - "
            if critical > 0:
                vuln_title += f"🔴 {critical} Critique(s) "
            if high > 0:
                vuln_title += f"🟠 {high} Élevé(s) "
            if medium > 0:
                vuln_title += f"🟡 {medium} Moyen(s)"

            vuln_frame = ttk.Labelframe(scrollable_frame, text=vuln_title, padding=15)
            vuln_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)

            # Afficher une note si beaucoup de vulnérabilités
            if len(vulnerabilities) > 20:
                note_frame = ttk.Frame(vuln_frame, bootstyle="info")
                note_frame.pack(fill=X, pady=5)
                ttk.Label(
                    note_frame,
                    text=f"ℹ️ Affichage des 20 vulnérabilités les plus critiques (sur {len(vulnerabilities)} total)",
                    font=("Segoe UI", 9),
                    bootstyle="info"
                ).pack(padx=10, pady=5)

            for vuln in vulnerabilities[:20]:  # Limiter à 20 vulnérabilités pour l'affichage
                severity = vuln.get('severity', 'INCONNU')
                cvss = vuln.get('cvss_score', 'N/A')
                cve_id = vuln.get('cve_id', 'N/A')
                port = vuln.get('port', 'N/A')
                service = vuln.get('service', 'N/A')
                description = vuln.get('description', 'Aucune description')

                # Couleur selon criticité
                severity_style = {
                    'CRITIQUE': 'danger',
                    'ÉLEVÉ': 'warning',
                    'MOYEN': 'info',
                    'FAIBLE': 'success',
                    'INCONNU': 'secondary'
                }.get(severity, 'secondary')

                emoji = {
                    'CRITIQUE': '🔴',
                    'ÉLEVÉ': '🟠',
                    'MOYEN': '🟡',
                    'FAIBLE': '🟢',
                    'INCONNU': '⚪'
                }.get(severity, '⚪')

                # Carte de vulnérabilité
                vuln_card = ttk.Frame(vuln_frame, relief='raised', borderwidth=1)
                vuln_card.pack(fill=X, pady=5)

                # En-tête
                vuln_header = ttk.Frame(vuln_card)
                vuln_header.pack(fill=X, padx=10, pady=5)

                ttk.Label(
                    vuln_header,
                    text=f"{emoji} {severity}",
                    font=('Segoe UI', 10, 'bold'),
                    bootstyle=severity_style
                ).pack(side=LEFT)

                ttk.Label(
                    vuln_header,
                    text=f"CVSS: {cvss}",
                    font=('Segoe UI', 9, 'bold')
                ).pack(side=LEFT, padx=10)

                # Détails
                details_frame = ttk.Frame(vuln_card)
                details_frame.pack(fill=X, padx=10, pady=2)

                ttk.Label(
                    details_frame,
                    text=f"CVE: {cve_id}",
                    font=('Courier', 9, 'bold')
                ).pack(anchor=W)

                ttk.Label(
                    details_frame,
                    text=f"Port: {port} ({service})",
                    font=('Segoe UI', 8)
                ).pack(anchor=W)

                ttk.Label(
                    details_frame,
                    text=description[:250] + ('...' if len(description) > 250 else ''),
                    font=('Segoe UI', 8),
                    wraplength=800
                ).pack(anchor=W, pady=2)

        elif result.get('vulnerabilities_summary') == 'Aucune':
            no_vuln_frame = ttk.Labelframe(scrollable_frame, text="🔒 Vulnérabilités", padding=15)
            no_vuln_frame.pack(fill=X, padx=5, pady=5)
            ttk.Label(
                no_vuln_frame,
                text="✅ Aucune vulnérabilité détectée",
                font=('Segoe UI', 11),
                bootstyle="success"
            ).pack()
        else:
            no_scan_frame = ttk.Labelframe(scrollable_frame, text="🔒 Vulnérabilités", padding=15)
            no_scan_frame.pack(fill=X, padx=5, pady=5)
            ttk.Label(
                no_scan_frame,
                text="⚠️ Scan de vulnérabilités non effectué",
                font=('Segoe UI', 10)
            ).pack()
            ttk.Label(
                no_scan_frame,
                text="Cliquez sur 'Scan Vulnérabilités' pour analyser",
                font=('Segoe UI', 9),
                foreground='gray'
            ).pack()

        # Bouton fermer
        close_btn = ttk.Button(
            scrollable_frame,
            text="✖ Fermer",
            command=details_window.destroy,
            bootstyle="secondary",
            width=20
        )
        close_btn.pack(pady=15)

        # Pack canvas et scrollbar
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

    def _save_to_history(self, results, duration):
        """
        Sauvegarde le scan dans l'historique

        Args:
            results: Résultats du scan
            duration: Durée du scan
        """
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'network': self.network_var.get(),
            'scan_type': self.scan_type_var.get(),
            'duration': duration,
            'hosts_found': len(results),
            'results': results
        }

        self.scan_history.insert(0, history_entry)

        # Limiter la taille de l'historique
        if len(self.scan_history) > 100:
            self.scan_history = self.scan_history[:100]

        # Sauvegarder
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur sauvegarde historique: {e}")

    def _load_history(self):
        """
        Charge l'historique des scans

        Returns:
            Liste des scans précédents
        """
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Erreur chargement historique: {e}")

        return []

    def _show_history(self):
        """
        Affiche l'historique des scans
        """
        if not self.scan_history:
            messagebox.showinfo("Historique", "Aucun scan dans l'historique")
            return

        # Fenêtre d'historique
        history_window = tk.Toplevel(self.root)
        history_window.title("Historique des scans")
        history_window.geometry("800x400")
        history_window.transient(self.root)

        # Treeview
        columns = ('Date', 'Réseau', 'Type', 'Hôtes', 'Durée')
        tree = ttk.Treeview(history_window, columns=columns, show='headings')

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)

        # Scrollbar
        vsb = ttk.Scrollbar(history_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)

        tree.pack(side=LEFT, fill=BOTH, expand=True)
        vsb.pack(side=RIGHT, fill=Y)

        # Remplir avec l'historique
        for entry in self.scan_history:
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
            tree.insert('', 'end', values=(
                timestamp,
                entry['network'],
                entry['scan_type'],
                entry['hosts_found'],
                format_scan_duration(entry['duration'])
            ))

        # Bouton de chargement
        def load_selected():
            selection = tree.selection()
            if selection:
                idx = tree.index(selection[0])
                entry = self.scan_history[idx]
                self.current_results = entry['results']
                self._display_results(entry['results'])
                history_window.destroy()

        ttk.Button(
            history_window,
            text="Charger le scan sélectionné",
            command=load_selected
        ).pack(pady=10)

    def _deep_scan_host(self):
        """
        Lance un scan approfondi sur un hôte spécifique avec plage de ports personnalisée
        """
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Aucune sélection", "Veuillez sélectionner un hôte")
            return

        # Récupérer l'index de l'item sélectionné dans le tree
        item = self.tree.item(selection[0])
        item_index = int(item['text']) - 1  # text contient l'index (commence à 1)

        # Récupérer le résultat correspondant depuis current_results
        # (même méthode que le scan de vulnérabilités qui fonctionne)
        if item_index < 0 or item_index >= len(self.current_results):
            messagebox.showerror("Erreur", "Impossible de récupérer les informations de l'hôte")
            logger.error(f"Index invalide: {item_index}, current_results length: {len(self.current_results)}")
            return

        result = self.current_results[item_index]
        ip = result['ip']  # Utiliser le même format d'IP que le scan de vulnérabilités
        logger.info(f"IP sélectionnée pour scan approfondi: '{ip}' (depuis current_results[{item_index}])")

        # Fenêtre de configuration du scan approfondi
        scan_window = tk.Toplevel(self.root)
        scan_window.title(f"🔍 Scan approfondi - {ip}")
        scan_window.geometry("650x700")
        scan_window.transient(self.root)
        scan_window.grab_set()

        # Frame principal avec scrollbar
        main_container = ttk.Frame(scan_window)
        main_container.pack(fill=BOTH, expand=True)

        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_container = ttk.Frame(canvas)

        scrollable_container.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_container, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Titre
        ttk.Label(
            scrollable_container,
            text=f"Scan approfondi de {ip}",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=20)

        # Frame de configuration des ports
        config_frame = ttk.Labelframe(scrollable_container, text="📍 Configuration des ports", padding=15)
        config_frame.pack(fill=X, padx=20, pady=10)

        # Plage de ports
        ports_frame = ttk.Frame(config_frame)
        ports_frame.pack(fill=X, pady=10)

        ttk.Label(ports_frame, text="Plage de ports:", font=("Segoe UI", 10, "bold")).pack(anchor=W)

        port_input_frame = ttk.Frame(ports_frame)
        port_input_frame.pack(fill=X, pady=5)

        ttk.Label(port_input_frame, text="Port de début:").pack(side=LEFT, padx=5)
        start_port_var = tk.StringVar(value="1")
        start_port_entry = ttk.Entry(port_input_frame, textvariable=start_port_var, width=10)
        start_port_entry.pack(side=LEFT, padx=5)

        ttk.Label(port_input_frame, text="Port de fin:").pack(side=LEFT, padx=5)
        end_port_var = tk.StringVar(value="1000")
        end_port_entry = ttk.Entry(port_input_frame, textvariable=end_port_var, width=10)
        end_port_entry.pack(side=LEFT, padx=5)

        # Exemples rapides
        examples_frame = ttk.Frame(config_frame)
        examples_frame.pack(fill=X, pady=5)

        ttk.Label(examples_frame, text="Exemples rapides:", font=("Segoe UI", 9)).pack(anchor=W)

        def set_common_ports():
            start_port_var.set("1")
            end_port_var.set("1024")

        def set_all_ports():
            start_port_var.set("1")
            end_port_var.set("65535")

        def set_high_ports():
            start_port_var.set("1024")
            end_port_var.set("49151")

        btn_frame = ttk.Frame(examples_frame)
        btn_frame.pack(fill=X, pady=5)

        ttk.Button(btn_frame, text="Ports communs (1-1024)", command=set_common_ports, width=20).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text="Tous les ports (1-65535)", command=set_all_ports, width=20).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text="Ports hauts (1024-49151)", command=set_high_ports, width=20).pack(side=LEFT, padx=2)

        # ===== PRESETS NMAP =====
        preset_frame = ttk.Labelframe(scrollable_container, text="🎯 Presets de scan Nmap", padding=15)
        preset_frame.pack(fill=X, padx=20, pady=10)

        ttk.Label(preset_frame, text="Utilisez un preset pré-configuré ou personnalisez manuellement ci-dessous:", font=("Segoe UI", 9, "italic")).pack(anchor=W, pady=5)

        preset_var = tk.StringVar(value="custom")

        from nmap_advanced import list_presets
        presets = list_presets()

        # Ajouter l'option "Custom"
        presets.insert(0, {'key': 'custom', 'name': 'Personnalisé', 'description': 'Configurer manuellement les options'})

        def apply_preset():
            """Applique les options du preset sélectionné"""
            preset_key = preset_var.get()
            if preset_key == 'custom':
                return

            from nmap_advanced import get_preset_options
            options = get_preset_options(preset_key)

            # Appliquer les options
            scan_type_var.set(options.get('scan_type', 'default'))
            timing_var.set(options.get('timing', 'T3'))
            os_detection_var.set(options.get('os_detection', False))
            version_detection_var.set(options.get('version_detection', False))
            traceroute_var.set(options.get('traceroute', False))

            # Scripts NSE
            script_option = options.get('script_scan', False)
            if isinstance(script_option, str):
                script_scan_var.set(True)
                script_category_var.set(script_option)
            else:
                script_scan_var.set(script_option)
                if script_option:
                    script_category_var.set('default')

            # Options avancées
            fragment_packets_var.set(options.get('fragment_packets', False))
            randomize_hosts_var.set(options.get('randomize_hosts', False))
            reason_var.set(options.get('reason', False))

            # Version intensity
            version_intensity_var.set(str(options.get('version_intensity', 7)))

            # Port range si spécifié
            port_range = options.get('port_range', '')
            if port_range and '-' in port_range:
                parts = port_range.split('-')
                if len(parts) == 2:
                    start_port_var.set(parts[0])
                    end_port_var.set(parts[1].split(',')[0])  # Prendre la première partie

            logger.info(f"Preset '{preset_key}' appliqué")

        # Créer les radio buttons pour les presets
        preset_buttons_frame = ttk.Frame(preset_frame)
        preset_buttons_frame.pack(fill=X, pady=5)

        row = 0
        col = 0
        for preset in presets:
            btn = ttk.Radiobutton(
                preset_buttons_frame,
                text=f"{preset['name']} - {preset['description'][:40]}...",
                variable=preset_var,
                value=preset['key'],
                command=apply_preset
            )
            btn.grid(row=row, column=0, sticky=W, padx=5, pady=2)
            row += 1

        # ===== OPTIONS NMAP =====
        nmap_frame = ttk.Labelframe(scrollable_container, text="⚙️ Options Nmap avancées", padding=15)
        nmap_frame.pack(fill=X, padx=20, pady=10)

        # Type de scan
        scan_type_frame = ttk.Frame(nmap_frame)
        scan_type_frame.pack(fill=X, pady=5)

        ttk.Label(scan_type_frame, text="Type de scan:", font=("Segoe UI", 10, "bold")).pack(anchor=W)

        scan_type_var = tk.StringVar(value="default")
        scan_types = [
            ("Par défaut (rapide)", "default"),
            ("SYN Scan -sS (nécessite root)", "syn"),
            ("TCP Connect -sT", "tcp"),
            ("UDP Scan -sU (nécessite root)", "udp"),
            ("FIN Scan -sF (furtif, nécessite root)", "fin"),
            ("NULL Scan -sN (très furtif, nécessite root)", "null"),
            ("XMAS Scan -sX (furtif, nécessite root)", "xmas"),
            ("Scan agressif -A (OS, version, scripts, traceroute)", "aggressive"),
        ]

        scan_type_col1 = ttk.Frame(nmap_frame)
        scan_type_col1.pack(fill=X, padx=20, pady=5)

        scan_type_col2 = ttk.Frame(nmap_frame)
        scan_type_col2.pack(fill=X, padx=20, pady=5)

        for i, (text, value) in enumerate(scan_types):
            parent = scan_type_col1 if i < 4 else scan_type_col2
            ttk.Radiobutton(
                parent,
                text=text,
                variable=scan_type_var,
                value=value
            ).pack(anchor=W)

        # Timing
        timing_frame = ttk.Frame(nmap_frame)
        timing_frame.pack(fill=X, pady=10)

        ttk.Label(timing_frame, text="Vitesse de scan (Timing):", font=("Segoe UI", 10, "bold")).pack(anchor=W)

        timing_var = tk.StringVar(value="T3")
        timing_desc_frame1 = ttk.Frame(nmap_frame)
        timing_desc_frame1.pack(fill=X, padx=20)

        timing_desc_frame2 = ttk.Frame(nmap_frame)
        timing_desc_frame2.pack(fill=X, padx=20, pady=2)

        # Première ligne
        ttk.Radiobutton(timing_desc_frame1, text="T0 - Paranoid (ultra lent)", variable=timing_var, value="T0").pack(side=LEFT, padx=5)
        ttk.Radiobutton(timing_desc_frame1, text="T1 - Sneaky (très lent)", variable=timing_var, value="T1").pack(side=LEFT, padx=5)
        ttk.Radiobutton(timing_desc_frame1, text="T2 - Polite (lent)", variable=timing_var, value="T2").pack(side=LEFT, padx=5)

        # Deuxième ligne
        ttk.Radiobutton(timing_desc_frame2, text="T3 - Normal", variable=timing_var, value="T3").pack(side=LEFT, padx=5)
        ttk.Radiobutton(timing_desc_frame2, text="T4 - Aggressive (rapide)", variable=timing_var, value="T4").pack(side=LEFT, padx=5)
        ttk.Radiobutton(timing_desc_frame2, text="T5 - Insane (très rapide)", variable=timing_var, value="T5").pack(side=LEFT, padx=5)

        # Options supplémentaires
        extra_options_frame = ttk.Frame(nmap_frame)
        extra_options_frame.pack(fill=X, pady=10)

        ttk.Label(extra_options_frame, text="Options de détection:", font=("Segoe UI", 10, "bold")).pack(anchor=W)

        os_detection_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            nmap_frame,
            text="Détection OS approfondie (-O)",
            variable=os_detection_var
        ).pack(anchor=W, padx=20, pady=2)

        version_detection_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            nmap_frame,
            text="Détection de version (-sV)",
            variable=version_detection_var
        ).pack(anchor=W, padx=20, pady=2)

        # Version intensity
        version_intensity_frame = ttk.Frame(nmap_frame)
        version_intensity_frame.pack(fill=X, padx=40, pady=2)

        ttk.Label(version_intensity_frame, text="Intensité de détection (0-9):").pack(side=LEFT, padx=5)
        version_intensity_var = tk.StringVar(value="7")
        version_intensity_spinbox = ttk.Spinbox(
            version_intensity_frame,
            from_=0,
            to=9,
            textvariable=version_intensity_var,
            width=5
        )
        version_intensity_spinbox.pack(side=LEFT, padx=5)
        ttk.Label(version_intensity_frame, text="(plus élevé = plus précis mais plus lent)", font=("Segoe UI", 8, "italic")).pack(side=LEFT)

        traceroute_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            nmap_frame,
            text="Traceroute (--traceroute)",
            variable=traceroute_var
        ).pack(anchor=W, padx=20, pady=2)

        # Scripts NSE
        ttk.Label(nmap_frame, text="Scripts NSE:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(10, 5))

        script_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            nmap_frame,
            text="Activer les scripts NSE",
            variable=script_scan_var
        ).pack(anchor=W, padx=20, pady=2)

        # Catégories de scripts
        script_category_frame = ttk.Frame(nmap_frame)
        script_category_frame.pack(fill=X, padx=40, pady=2)

        ttk.Label(script_category_frame, text="Catégorie:").pack(side=LEFT, padx=5)
        script_category_var = tk.StringVar(value="default")

        script_categories = [
            ("default", "Défaut"),
            ("vuln", "Vulnérabilités"),
            ("exploit", "Exploitation"),
            ("discovery", "Découverte"),
            ("safe", "Sûrs uniquement"),
            ("default,vuln", "Défaut + Vulnérabilités")
        ]

        script_category_combo = ttk.Combobox(
            script_category_frame,
            textvariable=script_category_var,
            values=[cat[0] for cat in script_categories],
            width=25,
            state="readonly"
        )
        script_category_combo.pack(side=LEFT, padx=5)

        # Options avancées
        ttk.Label(nmap_frame, text="Options avancées:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(10, 5))

        reason_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            nmap_frame,
            text="Afficher la raison de l'état des ports (--reason)",
            variable=reason_var
        ).pack(anchor=W, padx=20, pady=2)

        fragment_packets_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            nmap_frame,
            text="Fragmenter les paquets (-f) - pour éviter la détection",
            variable=fragment_packets_var
        ).pack(anchor=W, padx=20, pady=2)

        randomize_hosts_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            nmap_frame,
            text="Randomiser l'ordre des hôtes (--randomize-hosts)",
            variable=randomize_hosts_var
        ).pack(anchor=W, padx=20, pady=2)

        # Sauvegarde des résultats
        ttk.Label(nmap_frame, text="Sauvegarde des résultats:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(10, 5))

        save_output_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            nmap_frame,
            text="Sauvegarder les résultats (-oA)",
            variable=save_output_var
        ).pack(anchor=W, padx=20, pady=2)

        output_file_frame = ttk.Frame(nmap_frame)
        output_file_frame.pack(fill=X, padx=40, pady=2)

        ttk.Label(output_file_frame, text="Nom du fichier:").pack(side=LEFT, padx=5)
        output_file_var = tk.StringVar(value=f"scan_{ip.replace('.', '_')}")
        ttk.Entry(output_file_frame, textvariable=output_file_var, width=30).pack(side=LEFT, padx=5)
        ttk.Label(output_file_frame, text="(.nmap, .xml, .gnmap)", font=("Segoe UI", 8, "italic")).pack(side=LEFT)

        # ===== OPTIONS DE VULNÉRABILITÉS =====
        vuln_options_frame = ttk.Labelframe(scrollable_container, text="🔒 Options de scan de vulnérabilités", padding=15)
        vuln_options_frame.pack(fill=X, padx=20, pady=10)

        scan_vulns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            vuln_options_frame,
            text="Scanner les vulnérabilités après le scan de ports",
            variable=scan_vulns_var
        ).pack(anchor=W, pady=5)

        # Méthode de scan de vulnérabilités
        vuln_method_var = tk.StringVar(value="both")
        method_frame = ttk.Frame(vuln_options_frame)
        method_frame.pack(fill=X, pady=5)

        ttk.Label(method_frame, text="Méthode:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=5)
        ttk.Radiobutton(method_frame, text="Nmap NSE Scripts", variable=vuln_method_var, value="nmap").pack(anchor=W, padx=20)
        ttk.Radiobutton(method_frame, text="NVD API", variable=vuln_method_var, value="nvd").pack(anchor=W, padx=20)
        ttk.Radiobutton(method_frame, text="Les deux (recommandé)", variable=vuln_method_var, value="both").pack(anchor=W, padx=20)

        # Fonction de lancement
        def start_deep_scan():
            try:
                start_port = int(start_port_var.get())
                end_port = int(end_port_var.get())

                if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                    messagebox.showerror("Erreur", "Les ports doivent être entre 1 et 65535")
                    return

                if start_port > end_port:
                    messagebox.showerror("Erreur", "Le port de début doit être inférieur au port de fin")
                    return

                # Collecter toutes les options Nmap
                nmap_options = {
                    'scan_type': scan_type_var.get(),
                    'timing': timing_var.get(),
                    'os_detection': os_detection_var.get(),
                    'version_detection': version_detection_var.get(),
                    'traceroute': traceroute_var.get(),
                    'reason': reason_var.get(),
                    'fragment_packets': fragment_packets_var.get(),
                    'randomize_hosts': randomize_hosts_var.get(),
                    'port_range': f"{start_port}-{end_port}"  # Scanner TOUS les ports de la plage
                }

                # Version intensity (seulement si version_detection est activé)
                if version_detection_var.get():
                    try:
                        intensity = int(version_intensity_var.get())
                        if 0 <= intensity <= 9:
                            nmap_options['version_intensity'] = intensity
                    except ValueError:
                        pass

                # Scripts NSE (avec catégorie personnalisée)
                if script_scan_var.get():
                    nmap_options['script_scan'] = script_category_var.get()
                else:
                    nmap_options['script_scan'] = False

                # Output file (si sauvegarde activée)
                output_file = None
                if save_output_var.get():
                    output_file = output_file_var.get().strip()
                    if not output_file:
                        output_file = f"scan_{ip.replace('.', '_')}"

                # Vérifier si on a besoin des droits root
                import os
                needs_sudo = False
                if (nmap_options['scan_type'] in ['syn', 'aggressive', 'udp', 'fin', 'null', 'xmas'] or
                    nmap_options['os_detection'] or
                    nmap_options['traceroute']):
                    needs_sudo = os.geteuid() != 0

                logger.info(f"Options Nmap: {nmap_options}")
                logger.info(f"Needs sudo: {needs_sudo}, euid: {os.geteuid()}")

                sudo_password = None
                if needs_sudo:
                    logger.info("Demande du mot de passe sudo...")
                    # Demander le mot de passe sudo
                    sudo_password = self._ask_sudo_password()
                    logger.info(f"Mot de passe reçu: {'Oui' if sudo_password else 'Non'}")
                    if sudo_password is None:
                        # L'utilisateur a annulé
                        messagebox.showinfo(
                            "Information",
                            "Scan lancé sans privilèges root.\n\n"
                            "Certaines fonctionnalités seront limitées:\n"
                            "- OS detection\n"
                            "- SYN scan\n"
                            "- Traceroute"
                        )

                scan_window.destroy()
                self._execute_deep_scan(
                    ip, start_port, end_port,
                    scan_vulns_var.get(), vuln_method_var.get(),
                    nmap_options, sudo_password, output_file
                )

            except ValueError:
                messagebox.showerror("Erreur", "Veuillez entrer des numéros de ports valides")

        # Boutons
        button_frame = ttk.Frame(scrollable_container)
        button_frame.pack(fill=X, padx=20, pady=20)

        ttk.Button(
            button_frame,
            text="🚀 Démarrer le scan",
            command=start_deep_scan,
            bootstyle="success",
            width=20
        ).pack(side=LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="✖ Annuler",
            command=scan_window.destroy,
            bootstyle="secondary",
            width=15
        ).pack(side=RIGHT, padx=5)

    def _ask_sudo_password(self):
        """
        Demande le mot de passe sudo à l'utilisateur

        Returns:
            Le mot de passe ou None si annulé
        """
        password_window = tk.Toplevel(self.root)
        password_window.title("🔐 Authentification sudo requise")
        password_window.geometry("450x250")
        password_window.transient(self.root)
        password_window.grab_set()

        # Centrer la fenêtre
        password_window.update_idletasks()
        x = (password_window.winfo_screenwidth() // 2) - (450 // 2)
        y = (password_window.winfo_screenheight() // 2) - (250 // 2)
        password_window.geometry(f'450x250+{x}+{y}')

        password_var = tk.StringVar()
        result = {'password': None}

        # Titre
        ttk.Label(
            password_window,
            text="🔐 Privilèges root requis",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=20)

        # Explication
        ttk.Label(
            password_window,
            text="Les options sélectionnées nécessitent des privilèges root.\n"
                 "Veuillez entrer votre mot de passe sudo :",
            font=("Segoe UI", 10),
            justify="center"
        ).pack(pady=10)

        # Champ de mot de passe
        password_frame = ttk.Frame(password_window)
        password_frame.pack(pady=20)

        ttk.Label(password_frame, text="Mot de passe:", font=("Segoe UI", 10)).pack(side=LEFT, padx=5)
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="•", width=20)
        password_entry.pack(side=LEFT, padx=5)
        password_entry.focus()

        def validate_password():
            result['password'] = password_var.get()
            password_window.destroy()

        def cancel():
            password_window.destroy()

        # Boutons
        button_frame = ttk.Frame(password_window)
        button_frame.pack(pady=10)

        ttk.Button(
            button_frame,
            text="✓ Valider",
            command=validate_password,
            bootstyle="success",
            width=15
        ).pack(side=LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="✖ Annuler",
            command=cancel,
            bootstyle="secondary",
            width=15
        ).pack(side=LEFT, padx=5)

        # Permettre la validation avec Entrée
        password_entry.bind('<Return>', lambda e: validate_password())

        # Attendre la fermeture de la fenêtre
        password_window.wait_window()

        return result['password'] if result['password'] else None

    def _execute_deep_scan(self, ip: str, start_port: int, end_port: int, scan_vulns: bool, vuln_method: str, nmap_options: dict = None, sudo_password: str = None, output_file: str = None):
        """
        Exécute un scan approfondi sur un hôte avec options Nmap personnalisées

        Args:
            ip: Adresse IP à scanner
            start_port: Port de début
            end_port: Port de fin
            scan_vulns: Scanner les vulnérabilités
            vuln_method: Méthode de scan ('nmap', 'nvd', 'both')
            nmap_options: Options Nmap (scan_type, timing, os_detection, etc.)
            sudo_password: Mot de passe sudo (optionnel)
            output_file: Fichier de sortie pour -oA (optionnel)
        """
        if nmap_options is None:
            nmap_options = {
                'scan_type': 'default',
                'timing': 'T3',
                'os_detection': True,
                'version_detection': True,
                'script_scan': False,
                'traceroute': False
            }
        import threading
        from scanner import IPScanner
        import traceback

        # Créer la liste de ports
        port_list = list(range(start_port, end_port + 1))
        total_ports = len(port_list)

        # Message de confirmation
        logger.info(f"Démarrage scan approfondi: {ip}, ports {start_port}-{end_port} ({total_ports} ports)")

        # Flag pour arrêter le scan
        scan_control = {'running': True, 'nmap_process': None}

        # Créer la fenêtre de progression (plus grande pour afficher les détails)
        progress_window = tk.Toplevel(self.root)
        progress_window.title(f"Scan en cours - {ip}")
        progress_window.geometry("700x550")
        progress_window.transient(self.root)
        progress_window.grab_set()

        # Titre
        ttk.Label(
            progress_window,
            text=f"🔍 Scan approfondi de {ip}",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=15)

        # Info
        info_label = ttk.Label(
            progress_window,
            text=f"Scan de {total_ports} port(s) en cours...",
            font=("Segoe UI", 10)
        )
        info_label.pack(pady=5)

        # Barre de progression
        progress_bar = ttk.Progressbar(
            progress_window,
            mode='determinate',
            bootstyle="info",
            length=600
        )
        progress_bar.pack(pady=10)
        progress_bar['value'] = 0

        # Status
        status_label = ttk.Label(
            progress_window,
            text="Initialisation...",
            font=("Segoe UI", 9),
            bootstyle="secondary"
        )
        status_label.pack(pady=5)

        # Frame pour la zone de texte des ports détectés
        ports_frame = ttk.Labelframe(progress_window, text="📊 Ports analysés en temps réel", padding=10)
        ports_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

        # Zone de texte avec scrollbar pour afficher les ports
        ports_text_frame = ttk.Frame(ports_frame)
        ports_text_frame.pack(fill=BOTH, expand=True)

        ports_scrollbar = ttk.Scrollbar(ports_text_frame)
        ports_scrollbar.pack(side=RIGHT, fill=Y)

        ports_text = tk.Text(
            ports_text_frame,
            height=12,
            width=80,
            font=("Consolas", 9),
            yscrollcommand=ports_scrollbar.set,
            state='disabled'
        )
        ports_text.pack(side=LEFT, fill=BOTH, expand=True)
        ports_scrollbar.config(command=ports_text.yview)

        # Configurer les tags de couleur
        ports_text.tag_config('open', foreground='#28a745', font=("Consolas", 9, "bold"))
        ports_text.tag_config('closed', foreground='#6c757d')
        ports_text.tag_config('filtered', foreground='#ffc107')
        ports_text.tag_config('info', foreground='#17a2b8')
        ports_text.tag_config('header', foreground='#007bff', font=("Consolas", 9, "bold"))

        # Boutons
        button_frame = ttk.Frame(progress_window)
        button_frame.pack(pady=10)

        def stop_scan():
            """Arrêter le scan en cours"""
            scan_control['running'] = False
            if scan_control['nmap_process']:
                try:
                    scan_control['nmap_process'].terminate()
                    logger.info("Processus Nmap terminé")
                except:
                    pass
            status_label.config(text="⚠️ Arrêt du scan demandé...")
            stop_button.config(state=DISABLED)

        stop_button = ttk.Button(
            button_frame,
            text="⏹ Arrêter le scan",
            command=stop_scan,
            bootstyle="danger",
            width=20
        )
        stop_button.pack()

        # Désactiver les boutons
        self.btn_scan.config(state=DISABLED)
        self.status_var.set(f"Scan approfondi de {ip}: {total_ports} ports...")
        self.progress['value'] = 0

        # Compteur de ports scannés
        scan_stats = {'scanned': 0, 'open': 0, 'closed': 0, 'filtered': 0}

        def add_port_to_display(port_num, status, service="", version=""):
            """Ajoute un port à la zone de texte"""
            try:
                if not progress_window.winfo_exists():
                    return

                ports_text.config(state='normal')

                # Formatter la ligne selon le statut
                if status == 'open':
                    line = f"✓ Port {port_num:5d}/tcp   OUVERT   {service:15s} {version}\n"
                    tag = 'open'
                    scan_stats['open'] += 1
                elif status == 'closed':
                    line = f"✗ Port {port_num:5d}/tcp   fermé\n"
                    tag = 'closed'
                    scan_stats['closed'] += 1
                elif status == 'filtered':
                    line = f"? Port {port_num:5d}/tcp   filtré\n"
                    tag = 'filtered'
                    scan_stats['filtered'] += 1
                else:
                    line = f"  Port {port_num:5d}/tcp   {status}\n"
                    tag = 'info'

                ports_text.insert('end', line, tag)
                ports_text.see('end')  # Auto-scroll
                ports_text.config(state='disabled')

                scan_stats['scanned'] += 1

                # Mettre à jour la barre de progression
                if total_ports > 0:
                    progress = (scan_stats['scanned'] / total_ports) * 100
                    progress_bar['value'] = progress

            except Exception as e:
                logger.debug(f"Erreur affichage port: {e}")

        def update_progress_window(message: str, phase: str = "", current_port: int = None):
            """Met à jour la fenêtre de progression"""
            try:
                if not progress_window.winfo_exists():
                    return

                status_label.config(text=message)
                if phase:
                    info_label.config(text=phase)

                # Afficher les statistiques
                stats_text = f"Scannés: {scan_stats['scanned']}/{total_ports} | "
                stats_text += f"Ouverts: {scan_stats['open']} | "
                stats_text += f"Fermés: {scan_stats['closed']} | "
                stats_text += f"Filtrés: {scan_stats['filtered']}"

                if current_port:
                    stats_text += f" | Port actuel: {current_port}"

                info_label.config(text=stats_text)

            except Exception as e:
                logger.debug(f"Erreur update progress: {e}")

        # Ajouter un message d'en-tête dans la zone de texte
        ports_text.config(state='normal')
        ports_text.insert('end', f"🔍 Scan Nmap de {ip} - Ports {start_port}-{end_port}\n", 'header')
        ports_text.insert('end', f"{'='*70}\n\n", 'header')
        ports_text.config(state='disabled')

        # Gérer la fermeture de la fenêtre
        def on_window_close():
            """Arrêter le scan si la fenêtre est fermée"""
            scan_control['running'] = False
            if scan_control['nmap_process']:
                try:
                    scan_control['nmap_process'].terminate()
                except:
                    pass
            try:
                progress_window.destroy()
            except:
                pass

        progress_window.protocol("WM_DELETE_WINDOW", on_window_close)

        def scan_worker():
            try:
                logger.info(f"Thread de scan démarré pour {ip}")
                self.root.after(0, lambda: update_progress_window("Initialisation du scanner...", f"Scan de {total_ports} port(s)"))

                # Callback personnalisé pour mettre à jour la fenêtre de progression
                def progress_callback(msg: str, prog: int):
                    # Mettre à jour la barre de progression principale
                    self.root.after(0, lambda: self._update_progress(msg, prog))
                    # Mettre à jour la fenêtre de progression
                    self.root.after(0, lambda: update_progress_window(msg, f"Progression: {prog}%"))

                scanner = IPScanner(callback=progress_callback)

                # IMPORTANT: Activer le scanner (sinon scan_host retourne None)
                scanner.is_running = True

                # Configuration du scan
                # Pour un scan approfondi, on force le scan même si le ping échoue
                scan_config = {
                    'ping': False,  # Désactiver le ping pour forcer le scan de ports
                    'ports': True,
                    'port_list': port_list,
                    'mac_address': True,
                    'os_detection': True,
                    'service_detection': True,
                    'timeout': 1.0,
                    'use_scapy': self.has_root,
                    'force_scan': True  # Forcer le scan même si l'hôte semble offline
                }

                logger.info(f"Démarrage scan_host pour {ip}")
                self.root.after(0, lambda: update_progress_window(
                    f"Scan des ports {start_port}-{end_port}...",
                    f"Analyse de {total_ports} port(s)",
                    "Recherche de ports ouverts..."
                ))

                # Scanner l'hôte
                result = scanner.scan_host(ip, scan_config)
                logger.info(f"Scan_host terminé pour {ip}: {result is not None}")

                # Afficher les ports trouvés
                if result and result.get('open_ports'):
                    open_ports = result.get('open_ports', [])
                    port_list_str = ", ".join([str(p['port']) for p in open_ports[:10]])
                    if len(open_ports) > 10:
                        port_list_str += f"... (+{len(open_ports)-10} autres)"

                    self.root.after(0, lambda: update_progress_window(
                        f"Scan de ports terminé",
                        f"{len(open_ports)} port(s) ouvert(s) trouvé(s)",
                        f"Ports ouverts: {port_list_str}"
                    ))
                else:
                    self.root.after(0, lambda: update_progress_window(
                        f"Scan de ports terminé",
                        f"Aucun port ouvert trouvé",
                        ""
                    ))

                if result:
                    # Mettre à jour ou ajouter le résultat
                    existing = next((r for r in self.current_results if r['ip'] == ip), None)
                    if existing:
                        # Mettre à jour
                        existing.update(result)
                        logger.info(f"Résultat mis à jour pour {ip}")
                    else:
                        # Ajouter
                        self.current_results.append(result)
                        logger.info(f"Résultat ajouté pour {ip}")

                    # ===== SCAN NMAP AVANCÉ (si ports ouverts) =====
                    if result.get('open_ports'):
                        self.root.after(0, lambda: update_progress_window(
                            "Scan Nmap avancé en cours...",
                            "Collecte d'informations détaillées",
                            "OS, services, scripts NSE, traceroute..."
                        ))

                        from nmap_advanced import run_nmap_advanced_scan

                        # Callback pour afficher les ports en temps réel
                        def port_progress_callback(port_num, status, service, version):
                            """Callback appelé pour chaque port détecté"""
                            self.root.after(0, lambda: add_port_to_display(port_num, status, service, version))

                        # Scanner TOUS les ports de la plage avec Nmap, pas seulement ceux trouvés
                        # Cela garantit les mêmes résultats que la commande CLI
                        nmap_detailed = run_nmap_advanced_scan(
                            ip, None, nmap_options, sudo_password, output_file,
                            progress_callback=port_progress_callback,
                            scan_control=scan_control
                        )

                        # Ajouter les informations Nmap au résultat
                        result['nmap_detailed'] = nmap_detailed
                        logger.info(f"Scan Nmap avancé terminé pour {ip}")

                        # IMPORTANT: Remplacer les ports du scan basique par ceux de Nmap (plus précis et complets)
                        if nmap_detailed.get('detailed_ports'):
                            nmap_open_ports = []
                            for port_info in nmap_detailed['detailed_ports']:
                                if port_info.get('state', {}).get('state') == 'open':
                                    service_info = port_info.get('service', {})

                                    # Construire la version complète comme Nmap CLI
                                    version_parts = []
                                    if service_info.get('product'):
                                        version_parts.append(service_info['product'])
                                    if service_info.get('version'):
                                        version_parts.append(service_info['version'])
                                    if service_info.get('extrainfo'):
                                        version_parts.append(f"({service_info['extrainfo']})")
                                    version_str = ' '.join(version_parts) if version_parts else ''

                                    nmap_open_ports.append({
                                        'port': int(port_info['port']),
                                        'status': 'open',
                                        'service': service_info.get('name', 'unknown'),
                                        'version': version_str,
                                        'product': service_info.get('product', ''),
                                        'extrainfo': service_info.get('extrainfo', ''),
                                        'banner': ''  # Les bannières viennent des scripts si disponibles
                                    })

                            # Remplacer open_ports avec les résultats Nmap
                            if nmap_open_ports:
                                result['open_ports'] = nmap_open_ports
                                logger.info(f"Ports ouverts mis à jour avec les résultats Nmap: {len(nmap_open_ports)} ports")

                            # Mettre à jour le résumé des ports
                            if nmap_open_ports:
                                result['ports_summary'] = ', '.join([f"{p['port']}/{p['service']}" for p in nmap_open_ports[:5]])
                                if len(nmap_open_ports) > 5:
                                    result['ports_summary'] += f" (+{len(nmap_open_ports) - 5} more)"

                    # Scanner les vulnérabilités si demandé
                    if scan_vulns and result.get('open_ports'):
                        self.root.after(0, lambda: self.status_var.set(f"Scan vulnérabilités: {ip}..."))

                        open_ports_count = len(result.get('open_ports', []))
                        ports_list = ", ".join([str(p['port']) for p in result.get('open_ports', [])[:5]])
                        if open_ports_count > 5:
                            ports_list += f"... (+{open_ports_count-5})"

                        self.root.after(0, lambda pl=ports_list, opc=open_ports_count: update_progress_window(
                            f"Préparation du scan de vulnérabilités...",
                            f"{opc} port(s) ouvert(s) trouvé(s)",
                            f"Analyse des ports: {pl}"
                        ))
                        logger.info(f"Démarrage scan vulnérabilités pour {ip}")

                        from vulnerability_scan import scan_vulnerabilities_nmap, format_vulnerabilities_summary
                        from nvd_api import scan_vulnerabilities_nvd

                        vulnerabilities = []

                        # Scan Nmap
                        if vuln_method in ['nmap', 'both']:
                            ports = [p['port'] for p in result['open_ports']]
                            ports_str = ", ".join([str(p) for p in ports[:5]])
                            if len(ports) > 5:
                                ports_str += f"... (+{len(ports)-5})"

                            self.root.after(0, lambda ps=ports_str: update_progress_window(
                                "Scan Nmap NSE en cours...",
                                "Recherche de vulnérabilités",
                                f"Ports analysés: {ps}"
                            ))
                            nmap_result = scan_vulnerabilities_nmap(ip, ports=ports, timeout=180)
                            vulnerabilities.extend(nmap_result.get('vulnerabilities', []))

                        # Scan NVD
                        if vuln_method in ['nvd', 'both']:
                            self.root.after(0, lambda: update_progress_window(
                                "Scan NVD API en cours...",
                                "Recherche de CVE dans la base de données",
                                "Interrogation de l'API nationale des vulnérabilités..."
                            ))
                            nvd_result = scan_vulnerabilities_nvd(ip, result['open_ports'], max_per_service=10)
                            vulnerabilities.extend(nvd_result.get('vulnerabilities', []))

                        # Dédupliquer
                        seen_cves = set()
                        unique_vulns = []
                        for vuln in vulnerabilities:
                            cve_id = vuln.get('cve_id')
                            if cve_id not in seen_cves:
                                seen_cves.add(cve_id)
                                unique_vulns.append(vuln)

                        # Trier
                        severity_order = {'CRITIQUE': 0, 'ÉLEVÉ': 1, 'MOYEN': 2, 'FAIBLE': 3, 'INCONNU': 4}
                        unique_vulns.sort(key=lambda x: (severity_order.get(x.get('severity', 'INCONNU'), 5), -(x.get('cvss_score', 0) or 0)))

                        result['vulnerabilities'] = unique_vulns
                        result['vulnerabilities_summary'] = format_vulnerabilities_summary(unique_vulns)
                        logger.info(f"Scan vulnérabilités terminé: {len(unique_vulns)} trouvées")

                    # Réafficher les résultats
                    self.root.after(0, lambda: self._display_results(self.current_results))
                    self.root.after(0, lambda: self.status_var.set(f"Scan terminé: {ip} - {len(result.get('open_ports', []))} port(s) ouvert(s)"))

                    # Fermer la fenêtre de progression
                    self.root.after(0, lambda: progress_window.destroy() if progress_window.winfo_exists() else None)

                    # Afficher les résultats détaillés dans une fenêtre dédiée
                    self.root.after(100, lambda r=result.copy(), tp=total_ports, sv=scan_vulns:
                                   self._show_deep_scan_results(r, tp, sv))
                else:
                    logger.warning(f"Hôte {ip} inaccessible")
                    self.root.after(0, lambda: self.status_var.set(f"Hôte {ip} inaccessible"))

                    # Fermer la fenêtre de progression
                    self.root.after(0, lambda: progress_window.destroy() if progress_window.winfo_exists() else None)

                    self.root.after(100, lambda: messagebox.showwarning(
                        "Hôte inaccessible",
                        f"L'hôte {ip} n'a pas répondu au scan."
                    ))

            except Exception as e:
                error_msg = f"Erreur lors du scan de {ip}: {str(e)}\n{traceback.format_exc()}"
                logger.error(error_msg)

                # Fermer la fenêtre de progression
                self.root.after(0, lambda: progress_window.destroy() if progress_window.winfo_exists() else None)

                self.root.after(100, lambda: messagebox.showerror(
                    "Erreur de scan",
                    f"Une erreur est survenue lors du scan:\n\n{str(e)}"
                ))
            finally:
                self.root.after(0, lambda: self.btn_scan.config(state=NORMAL))
                self.root.after(0, lambda: self.progress.update_idletasks())
                # S'assurer que la fenêtre de progression est fermée
                try:
                    if progress_window.winfo_exists():
                        self.root.after(0, lambda: progress_window.destroy())
                except:
                    pass

        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()

    def _show_deep_scan_results(self, result: dict, total_ports: int, scan_vulns: bool):
        """
        Affiche les résultats détaillés du scan approfondi dans une fenêtre dédiée

        Args:
            result: Résultat du scan
            total_ports: Nombre total de ports scannés
            scan_vulns: Si le scan de vulnérabilités a été effectué
        """
        ip = result['ip']
        open_ports = result.get('open_ports', [])
        vulnerabilities = result.get('vulnerabilities', [])

        # Fenêtre de résultats
        results_window = tk.Toplevel(self.root)
        results_window.title(f"🔍 Résultats du scan approfondi - {ip}")
        results_window.geometry("900x700")
        results_window.transient(self.root)

        # Frame principal avec scrollbar
        main_frame = ttk.Frame(results_window)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(main_frame, bg='#f0f0f0', highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Titre
        title_frame = ttk.Frame(scrollable_frame)
        title_frame.pack(fill=X, pady=(0, 20))

        ttk.Label(
            title_frame,
            text=f"📊 Résultats du scan approfondi",
            font=("Segoe UI", 16, "bold")
        ).pack()

        ttk.Label(
            title_frame,
            text=f"Hôte: {ip}",
            font=("Segoe UI", 12)
        ).pack()

        # ===== SECTION RÉSUMÉ =====
        summary_frame = ttk.Labelframe(scrollable_frame, text="📋 Résumé", padding=15)
        summary_frame.pack(fill=X, padx=10, pady=10)

        summary_info = [
            ("Ports scannés", f"{total_ports}"),
            ("Ports ouverts", f"{len(open_ports)}", "success" if open_ports else "secondary"),
            ("Services détectés", f"{sum(1 for p in open_ports if p.get('service') != 'unknown')}"),
        ]

        if scan_vulns:
            vuln_count = len(vulnerabilities)
            critical = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITIQUE')
            high = sum(1 for v in vulnerabilities if v.get('severity') == 'ÉLEVÉ')
            medium = sum(1 for v in vulnerabilities if v.get('severity') == 'MOYEN')

            vuln_text = f"{vuln_count}"
            if critical > 0:
                vuln_text += f" (🔴 {critical} critique{'s' if critical > 1 else ''})"
            if high > 0:
                vuln_text += f" (🟠 {high} élevé{'s' if high > 1 else ''})"
            if medium > 0:
                vuln_text += f" (🟡 {medium} moyen{'s' if medium > 1 else ''})"

            summary_info.append(("Vulnérabilités", vuln_text, "danger" if critical > 0 else ("warning" if high > 0 else "info")))

        for i, info in enumerate(summary_info):
            info_frame = ttk.Frame(summary_frame)
            info_frame.pack(fill=X, pady=5)

            ttk.Label(
                info_frame,
                text=f"{info[0]}:",
                font=("Segoe UI", 10, "bold"),
                width=20
            ).pack(side=LEFT)

            style = info[2] if len(info) > 2 else "primary"
            ttk.Label(
                info_frame,
                text=info[1],
                bootstyle=style,
                font=("Segoe UI", 10)
            ).pack(side=LEFT)

        # ===== FICHIERS DE SORTIE NMAP =====
        nmap_detailed = result.get('nmap_detailed', {})
        output_files = nmap_detailed.get('output_files', [])

        if output_files:
            files_frame = ttk.Labelframe(scrollable_frame, text="💾 Fichiers de résultats Nmap créés", padding=15)
            files_frame.pack(fill=X, padx=10, pady=10)

            ttk.Label(
                files_frame,
                text="Les résultats du scan ont été sauvegardés dans les fichiers suivants:",
                font=("Segoe UI", 9, "italic")
            ).pack(anchor=W, pady=(0, 10))

            for file_path in output_files:
                file_item_frame = ttk.Frame(files_frame)
                file_item_frame.pack(fill=X, pady=2)

                # Icône selon le type de fichier
                import os
                file_ext = os.path.splitext(file_path)[1]
                icon = "📄"
                if file_ext == ".xml":
                    icon = "📋"
                elif file_ext == ".gnmap":
                    icon = "🔍"

                ttk.Label(
                    file_item_frame,
                    text=f"{icon} {file_path}",
                    font=("Segoe UI", 9)
                ).pack(side=LEFT, padx=5)

                # Vérifier si le fichier existe
                if os.path.exists(file_path):
                    ttk.Label(
                        file_item_frame,
                        text="✓ Créé",
                        font=("Segoe UI", 8),
                        bootstyle="success"
                    ).pack(side=LEFT, padx=5)
                else:
                    ttk.Label(
                        file_item_frame,
                        text="✗ Non trouvé",
                        font=("Segoe UI", 8),
                        bootstyle="warning"
                    ).pack(side=LEFT, padx=5)

        # ===== INFORMATIONS NMAP DÉTAILLÉES =====

        # Debug : afficher ce qu'on a reçu
        logger.info(f"=== AFFICHAGE RÉSULTATS ===")
        logger.info(f"nmap_detailed présent: {bool(nmap_detailed)}")
        logger.info(f"os_details: {bool(nmap_detailed.get('os_details'))}")
        logger.info(f"traceroute: {len(nmap_detailed.get('traceroute', []))}")
        logger.info(f"detailed_ports: {len(nmap_detailed.get('detailed_ports', []))}")
        logger.info(f"scripts_output: {len(nmap_detailed.get('scripts_output', {}))}")
        if nmap_detailed.get('os_details'):
            logger.info(f"OS details content: {nmap_detailed['os_details']}")

        # OS Detection détaillée
        if nmap_detailed.get('os_details'):
            os_frame = ttk.Labelframe(scrollable_frame, text="💻 Détection OS avancée (Nmap)", padding=15)
            os_frame.pack(fill=X, padx=10, pady=10)

            os_info = nmap_detailed['os_details']
            os_data = [
                ("Système d'exploitation", os_info.get('name', 'Inconnu')),
                ("Confiance", f"{os_info.get('accuracy', '0')}%"),
                ("Type", os_info.get('type', 'N/A')),
                ("Fabricant", os_info.get('vendor', 'N/A')),
                ("Famille", os_info.get('family', 'N/A'))
            ]

            for label, value in os_data:
                if value and value != 'N/A' and value != '':
                    item_frame = ttk.Frame(os_frame)
                    item_frame.pack(fill=X, pady=2)

                    ttk.Label(
                        item_frame,
                        text=f"{label}:",
                        font=("Segoe UI", 9, "bold"),
                        width=25
                    ).pack(side=LEFT)

                    ttk.Label(
                        item_frame,
                        text=value,
                        font=("Segoe UI", 9)
                    ).pack(side=LEFT)

        # Traceroute
        if nmap_detailed.get('traceroute'):
            trace_frame = ttk.Labelframe(scrollable_frame, text=f"🌐 Traceroute ({len(nmap_detailed['traceroute'])} sauts)", padding=15)
            trace_frame.pack(fill=X, padx=10, pady=10)

            # Créer un tableau pour le traceroute
            trace_tree_frame = ttk.Frame(trace_frame)
            trace_tree_frame.pack(fill=BOTH, expand=True)

            trace_tree_scroll = ttk.Scrollbar(trace_tree_frame)
            trace_tree_scroll.pack(side=RIGHT, fill=Y)

            trace_tree = ttk.Treeview(
                trace_tree_frame,
                columns=("ttl", "ip", "host", "rtt"),
                show="headings",
                height=min(len(nmap_detailed['traceroute']), 8),
                yscrollcommand=trace_tree_scroll.set
            )

            trace_tree.heading("ttl", text="TTL")
            trace_tree.heading("ip", text="Adresse IP")
            trace_tree.heading("host", text="Hôte")
            trace_tree.heading("rtt", text="RTT (ms)")

            trace_tree.column("ttl", width=50)
            trace_tree.column("ip", width=150)
            trace_tree.column("host", width=250)
            trace_tree.column("rtt", width=100)

            for hop in nmap_detailed['traceroute']:
                trace_tree.insert('', 'end', values=(
                    hop.get('ttl', ''),
                    hop.get('ip', ''),
                    hop.get('host', ''),
                    hop.get('rtt', '')
                ))

            trace_tree.pack(side=LEFT, fill=BOTH, expand=True)
            trace_tree_scroll.config(command=trace_tree.yview)

        # Scripts NSE exécutés (host-level)
        if nmap_detailed.get('scripts_output'):
            scripts_frame = ttk.Labelframe(scrollable_frame, text=f"📜 Scripts NSE exécutés ({len(nmap_detailed['scripts_output'])})", padding=15)
            scripts_frame.pack(fill=X, padx=10, pady=10)

            for script_id, output in list(nmap_detailed['scripts_output'].items())[:5]:
                script_card = ttk.Frame(scripts_frame, relief='solid', borderwidth=1)
                script_card.pack(fill=X, pady=5, padx=5)

                ttk.Label(
                    script_card,
                    text=script_id,
                    font=("Segoe UI", 9, "bold"),
                    bootstyle="info"
                ).pack(anchor=W, padx=10, pady=(10, 5))

                ttk.Label(
                    script_card,
                    text=output[:300] + ("..." if len(output) > 300 else ""),
                    font=("Courier", 8),
                    wraplength=850
                ).pack(anchor=W, padx=10, pady=(0, 10))

        # ===== SECTION PORTS OUVERTS =====
        if open_ports:
            ports_frame = ttk.Labelframe(scrollable_frame, text=f"🔌 Ports ouverts ({len(open_ports)})", padding=15)
            ports_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

            # Créer un tableau pour les ports
            ports_tree_frame = ttk.Frame(ports_frame)
            ports_tree_frame.pack(fill=BOTH, expand=True)

            ports_tree_scroll = ttk.Scrollbar(ports_tree_frame)
            ports_tree_scroll.pack(side=RIGHT, fill=Y)

            ports_tree = ttk.Treeview(
                ports_tree_frame,
                columns=("port", "service", "version", "banner"),
                show="headings",
                height=min(len(open_ports), 10),
                yscrollcommand=ports_tree_scroll.set
            )

            ports_tree.heading("port", text="Port")
            ports_tree.heading("service", text="Service")
            ports_tree.heading("version", text="Version")
            ports_tree.heading("banner", text="Bannière")

            ports_tree.column("port", width=80)
            ports_tree.column("service", width=120)
            ports_tree.column("version", width=150)
            ports_tree.column("banner", width=400)

            for port_info in open_ports:
                port = port_info.get('port', '')
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                banner = port_info.get('banner', '')[:100]  # Limiter la taille

                ports_tree.insert('', 'end', values=(port, service, version, banner))

            ports_tree.pack(side=LEFT, fill=BOTH, expand=True)
            ports_tree_scroll.config(command=ports_tree.yview)

        else:
            no_ports_frame = ttk.Labelframe(scrollable_frame, text="🔌 Ports ouverts", padding=15)
            no_ports_frame.pack(fill=X, padx=10, pady=10)

            ttk.Label(
                no_ports_frame,
                text="Aucun port ouvert détecté",
                font=("Segoe UI", 10),
                bootstyle="secondary"
            ).pack()

        # ===== SECTION VULNÉRABILITÉS =====
        if scan_vulns:
            if vulnerabilities:
                vuln_frame = ttk.Labelframe(
                    scrollable_frame,
                    text=f"🔒 Vulnérabilités détectées ({len(vulnerabilities)}) - Scan sur ports ouverts uniquement",
                    padding=15
                )
                vuln_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

                # Limiter l'affichage
                display_vulns = vulnerabilities[:20]
                if len(vulnerabilities) > 20:
                    ttk.Label(
                        vuln_frame,
                        text=f"⚠️ Affichage des 20 vulnérabilités les plus critiques sur {len(vulnerabilities)} trouvées",
                        font=("Segoe UI", 9, "italic"),
                        bootstyle="warning"
                    ).pack(pady=(0, 10))

                for vuln in display_vulns:
                    vuln_card = ttk.Frame(vuln_frame, relief='raised', borderwidth=1)
                    vuln_card.pack(fill=X, pady=5, padx=5)

                    # Ligne 1: CVE + Criticité
                    header_frame = ttk.Frame(vuln_card)
                    header_frame.pack(fill=X, padx=10, pady=(10, 5))

                    cve_id = vuln.get('cve_id', 'N/A')
                    ttk.Label(
                        header_frame,
                        text=cve_id,
                        font=("Segoe UI", 10, "bold")
                    ).pack(side=LEFT)

                    severity = vuln.get('severity', 'INCONNU')
                    cvss_score = vuln.get('cvss_score')
                    score_text = f"CVSS: {cvss_score}" if cvss_score else ""

                    severity_style = {
                        'CRITIQUE': 'danger',
                        'ÉLEVÉ': 'warning',
                        'MOYEN': 'info',
                        'FAIBLE': 'secondary',
                        'INCONNU': 'secondary'
                    }.get(severity, 'secondary')

                    ttk.Label(
                        header_frame,
                        text=f"{severity} {score_text}",
                        bootstyle=severity_style,
                        font=("Segoe UI", 9, "bold")
                    ).pack(side=RIGHT)

                    # Ligne 2: Port + Service
                    port_frame = ttk.Frame(vuln_card)
                    port_frame.pack(fill=X, padx=10, pady=5)

                    port = vuln.get('port', '')
                    service = vuln.get('service', '')
                    version = vuln.get('version', '')

                    port_text = f"Port: {port}"
                    if service:
                        port_text += f" | Service: {service}"
                    if version:
                        port_text += f" {version}"

                    ttk.Label(
                        port_frame,
                        text=port_text,
                        font=("Segoe UI", 9),
                        bootstyle="secondary"
                    ).pack(side=LEFT)

                    # Ligne 3: Description
                    desc_frame = ttk.Frame(vuln_card)
                    desc_frame.pack(fill=X, padx=10, pady=(5, 10))

                    description = vuln.get('description', '')[:200]
                    ttk.Label(
                        desc_frame,
                        text=description,
                        font=("Segoe UI", 9),
                        wraplength=800
                    ).pack(side=LEFT, fill=X, expand=True)

            elif open_ports:
                # Scan de vulnérabilités effectué mais aucune trouvée
                vuln_frame = ttk.Labelframe(scrollable_frame, text="🔒 Vulnérabilités", padding=15)
                vuln_frame.pack(fill=X, padx=10, pady=10)

                ttk.Label(
                    vuln_frame,
                    text=f"✅ Aucune vulnérabilité détectée sur les {len(open_ports)} port(s) ouvert(s)",
                    font=("Segoe UI", 10),
                    bootstyle="success"
                ).pack()
            else:
                # Pas de ports ouverts donc pas de scan de vulnérabilités
                vuln_frame = ttk.Labelframe(scrollable_frame, text="🔒 Vulnérabilités", padding=15)
                vuln_frame.pack(fill=X, padx=10, pady=10)

                ttk.Label(
                    vuln_frame,
                    text="⚠️ Aucun port ouvert détecté - Scan de vulnérabilités non effectué",
                    font=("Segoe UI", 10),
                    bootstyle="warning"
                ).pack()

        # Bouton fermer
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.pack(fill=X, pady=20)

        ttk.Button(
            button_frame,
            text="✖ Fermer",
            command=results_window.destroy,
            bootstyle="secondary",
            width=15
        ).pack()

        # Pack canvas et scrollbar
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Bind mousewheel
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", on_mousewheel)

    def _show_theme_selector(self):
        """
        Affiche la fenêtre de sélection de thèmes
        """
        # Fenêtre de sélection de thèmes
        theme_window = tk.Toplevel(self.root)
        theme_window.title("Sélection du thème")
        theme_window.geometry("700x550")
        theme_window.transient(self.root)
        theme_window.grab_set()

        # Titre
        ttk.Label(
            theme_window,
            text="🎨 Choisissez un thème",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=20)

        # Description
        ttk.Label(
            theme_window,
            text="Sélectionnez un thème pour personnaliser l'apparence de l'application",
            font=("Segoe UI", 10)
        ).pack(pady=(0, 20))

        # Liste des thèmes disponibles
        available_themes = [
            "cosmo", "flatly", "litera", "minty", "lumen", "sandstone",
            "yeti", "pulse", "united", "morph", "journal", "darkly",
            "superhero", "solar", "cyborg", "vapor", "simplex", "cerculean"
        ]

        # Thème actuel
        current_theme_name = self.root.style.theme.name

        # Frame pour la grille de thèmes
        themes_frame = ttk.Frame(theme_window)
        themes_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

        # Créer une grille de boutons pour chaque thème (4 colonnes)
        for idx, theme_name in enumerate(available_themes):
            row = idx // 4
            col = idx % 4

            # Frame pour chaque thème
            theme_btn_frame = ttk.Frame(themes_frame)
            theme_btn_frame.grid(row=row, column=col, padx=5, pady=5, sticky=(W, E))

            # Indicateur si c'est le thème actuel
            label_text = f"✓ {theme_name.upper()}" if theme_name == current_theme_name else theme_name.upper()
            btn_style = "success" if theme_name == current_theme_name else "primary"

            # Bouton pour sélectionner le thème
            def make_apply_theme(theme):
                def apply_theme():
                    try:
                        # Changer le thème
                        self.root.style.theme_use(theme)

                        # Sauvegarder le thème dans un fichier de configuration
                        import json
                        config_file = Path("theme_config.json")
                        config_file.write_text(json.dumps({"theme": theme}))

                        # Fermer la fenêtre
                        theme_window.destroy()

                        # Message de confirmation
                        messagebox.showinfo(
                            "Thème appliqué",
                            f"Le thème '{theme}' a été appliqué avec succès!\n\n"
                            "Le thème sera conservé au prochain démarrage."
                        )
                    except Exception as e:
                        messagebox.showerror("Erreur", f"Erreur lors de l'application du thème:\n{e}")

                return apply_theme

            ttk.Button(
                theme_btn_frame,
                text=label_text,
                command=make_apply_theme(theme_name),
                bootstyle=btn_style,
                width=15
            ).pack(fill=X)

        # Configurer les colonnes pour qu'elles se redimensionnent
        for i in range(4):
            themes_frame.columnconfigure(i, weight=1)

        # Frame pour les boutons en bas
        button_frame = ttk.Frame(theme_window)
        button_frame.pack(fill=X, padx=20, pady=20)

        # Bouton Quitter
        ttk.Button(
            button_frame,
            text="✖  Fermer",
            command=theme_window.destroy,
            bootstyle="secondary",
            width=15
        ).pack(side=RIGHT, padx=5)

        # Bouton Info
        def show_theme_info():
            messagebox.showinfo(
                "À propos des thèmes",
                "L'application utilise ttkbootstrap pour les thèmes.\n\n"
                "Thèmes clairs recommandés:\n"
                "• cosmo, flatly, litera, minty, lumen, sandstone, yeti, simplex\n\n"
                "Thèmes sombres:\n"
                "• darkly, superhero, solar, cyborg, vapor\n\n"
                "Le thème sélectionné sera sauvegardé et appliqué automatiquement\n"
                "au prochain démarrage de l'application."
            )

        ttk.Button(
            button_frame,
            text="ℹ  Info",
            command=show_theme_info,
            bootstyle="info-outline",
            width=15
        ).pack(side=LEFT, padx=5)

    def _scan_vulnerabilities(self):
        """
        Lance le scan de vulnérabilités sur les hôtes trouvés
        """
        if not self.current_results:
            messagebox.showwarning(
                "Aucun hôte",
                "Aucun hôte à scanner.\n\nVeuillez d'abord effectuer un scan réseau."
            )
            return

        # Fenêtre de choix de la méthode
        choice_window = tk.Toplevel(self.root)
        choice_window.title("Méthode de scan de vulnérabilités")
        choice_window.geometry("500x300")
        choice_window.transient(self.root)
        choice_window.grab_set()

        ttk.Label(
            choice_window,
            text="Choisissez la méthode de scan:",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=20)

        scan_method = tk.StringVar(value="both")

        # Option Nmap
        nmap_frame = ttk.Labelframe(choice_window, text="Nmap NSE Scripts", padding=10)
        nmap_frame.pack(fill=X, padx=20, pady=5)

        ttk.Radiobutton(
            nmap_frame,
            text="Nmap uniquement (Local, rapide, nécessite Nmap installé)",
            variable=scan_method,
            value="nmap"
        ).pack(anchor=W)

        # Option NVD
        nvd_frame = ttk.Labelframe(choice_window, text="API NVD", padding=10)
        nvd_frame.pack(fill=X, padx=20, pady=5)

        ttk.Radiobutton(
            nvd_frame,
            text="NVD API uniquement (En ligne, base à jour, plus lent)",
            variable=scan_method,
            value="nvd"
        ).pack(anchor=W)

        # Option les deux
        both_frame = ttk.Labelframe(choice_window, text="Combiné (Recommandé)", padding=10)
        both_frame.pack(fill=X, padx=20, pady=5)

        ttk.Radiobutton(
            both_frame,
            text="Nmap + NVD API (Plus complet, combine les deux méthodes)",
            variable=scan_method,
            value="both"
        ).pack(anchor=W)

        def start_scan():
            method = scan_method.get()
            choice_window.destroy()
            self._execute_vulnerability_scan(method)

        ttk.Button(
            choice_window,
            text="Démarrer le scan",
            command=start_scan,
            bootstyle="success"
        ).pack(pady=20)

        ttk.Button(
            choice_window,
            text="Annuler",
            command=choice_window.destroy,
            bootstyle="secondary"
        ).pack()

    def _execute_vulnerability_scan(self, method: str):
        """
        Exécute le scan de vulnérabilités selon la méthode choisie

        Args:
            method: 'nmap', 'nvd', ou 'both'
        """
        # Vérifications selon la méthode
        if method in ['nmap', 'both']:
            from vulnerability_scan import check_nmap_installed
            if not check_nmap_installed():
                messagebox.showerror(
                    "Nmap non installé",
                    "Nmap n'est pas installé.\n\n"
                    "Pour installer:\n"
                    "sudo apt install nmap\n\n"
                    "Voulez-vous continuer avec NVD API uniquement?"
                )
                if method == 'nmap':
                    return
                method = 'nvd'

        # Désactiver le bouton pendant le scan
        self.btn_vuln_scan.config(state=DISABLED)
        self.status_var.set(f"Scan de vulnérabilités ({method.upper()}) en cours...")
        self.progress['value'] = 0

        # Lancer le scan dans un thread séparé
        import threading
        from vulnerability_scan import scan_vulnerabilities_nmap, format_vulnerabilities_summary
        from nvd_api import scan_vulnerabilities_nvd

        def scan_worker():
            total = len(self.current_results)
            all_vulnerabilities = []

            for idx, result in enumerate(self.current_results):
                ip = result['ip']

                # Mettre à jour la progression
                progress = int((idx / total) * 100)
                self.root.after(0, lambda p=progress: self.progress.update_idletasks())
                self.root.after(0, lambda msg=f"Scan {method.upper()}: {ip} ({idx+1}/{total})": self.status_var.set(msg))

                # Récupérer les ports ouverts
                open_ports = result.get('open_ports', [])
                vulnerabilities = []

                # Scan Nmap
                if method in ['nmap', 'both']:
                    self.root.after(0, lambda: self.status_var.set(f"Nmap scan: {ip}"))
                    ports_list = [p['port'] for p in open_ports] if open_ports else None
                    nmap_result = scan_vulnerabilities_nmap(ip, ports=ports_list, timeout=180)
                    vulnerabilities.extend(nmap_result.get('vulnerabilities', []))

                # Scan NVD API
                if method in ['nvd', 'both']:
                    self.root.after(0, lambda: self.status_var.set(f"NVD API scan: {ip}"))
                    nvd_result = scan_vulnerabilities_nvd(ip, open_ports, max_per_service=10)
                    vulnerabilities.extend(nvd_result.get('vulnerabilities', []))

                # Dédupliquer les vulnérabilités (même CVE)
                seen_cves = set()
                unique_vulns = []
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cve_id')
                    if cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        unique_vulns.append(vuln)

                # Trier par criticité
                severity_order = {'CRITIQUE': 0, 'ÉLEVÉ': 1, 'MOYEN': 2, 'FAIBLE': 3, 'INCONNU': 4}
                unique_vulns.sort(key=lambda x: (severity_order.get(x.get('severity', 'INCONNU'), 5), -(x.get('cvss_score', 0) or 0)))

                # Mettre à jour le résultat
                result['vulnerabilities'] = unique_vulns
                result['vulnerabilities_summary'] = format_vulnerabilities_summary(unique_vulns)

                all_vulnerabilities.extend(unique_vulns)

            # Statistiques
            total_vulns = len(all_vulnerabilities)
            critical = sum(1 for v in all_vulnerabilities if v.get('severity') == 'CRITIQUE')
            high = sum(1 for v in all_vulnerabilities if v.get('severity') == 'ÉLEVÉ')

            # Réafficher les résultats
            self.root.after(0, lambda: self._display_results(self.current_results))
            self.root.after(0, lambda: self.status_var.set(f"Scan terminé - {total_vulns} vulnérabilité(s) trouvée(s)"))
            self.root.after(0, lambda: self.btn_vuln_scan.config(state=NORMAL))
            self.root.after(0, lambda: messagebox.showinfo(
                "Scan terminé",
                f"Scan de vulnérabilités ({method.upper()}) terminé!\n\n"
                f"• Hôtes scannés: {total}\n"
                f"• Vulnérabilités trouvées: {total_vulns}\n"
                f"  - 🔴 Critiques: {critical}\n"
                f"  - 🟠 Élevées: {high}\n\n"
                "Double-cliquez sur un hôte pour voir les détails."
            ))

        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()

    # ========================================================================
    # FONCTIONS DU SCANNER WIFI
    # ========================================================================

    def _refresh_wifi_interfaces(self):
        """Rafraîchit la liste des interfaces WiFi"""
        if not self.wifi_scanner:
            return

        interfaces = self.wifi_scanner.get_wifi_interfaces()
        self.wifi_interface_combo['values'] = interfaces

        if interfaces:
            self.wifi_interface_combo.current(0)
            self.wifi_status_var.set(f"Interfaces WiFi détectées: {len(interfaces)}")
        else:
            self.wifi_status_var.set("Aucune interface WiFi détectée")

    def _toggle_monitor_mode(self):
        """Active/désactive le mode moniteur"""
        if not self.wifi_scanner:
            return

        if not self.wifi_monitor_mode_active:
            # Activer le mode moniteur
            interface = self.wifi_interface_var.get()
            if not interface:
                messagebox.showwarning("Attention", "Sélectionnez une interface WiFi")
                return

            self.wifi_status_var.set("Activation du mode moniteur...")
            self.wifi_progress['value'] = 30

            def activate_monitor():
                mon_interface = self.wifi_scanner.enable_monitor_mode(interface)

                if mon_interface:
                    self.wifi_monitor_interface = mon_interface
                    self.wifi_monitor_mode_active = True

                    self.root.after(0, lambda: self.btn_monitor_mode.config(
                        text="🛑 Désactiver Mode Moniteur",
                        bootstyle="danger"
                    ))
                    self.root.after(0, lambda: self.btn_scan_wifi.config(state=NORMAL))
                    self.root.after(0, lambda: self.wifi_monitor_status_var.set(
                        f"Mode moniteur: Actif ({mon_interface})"
                    ))
                    self.root.after(0, lambda: self.wifi_status_var.set(
                        f"Mode moniteur activé: {mon_interface}"
                    ))
                    self.root.after(0, lambda: self.wifi_progress.config(value=100))
                else:
                    self.root.after(0, lambda: self.wifi_status_var.set(
                        "Échec activation mode moniteur"
                    ))
                    self.root.after(0, lambda: self.wifi_progress.config(value=0))
                    self.root.after(0, lambda: messagebox.showerror(
                        "Erreur",
                        "Échec de l'activation du mode moniteur.\n\n"
                        "Vérifiez que:\n"
                        "• Vous avez les droits root/sudo\n"
                        "• L'interface supporte le mode moniteur\n"
                        "• airmon-ng est installé"
                    ))

            threading.Thread(target=activate_monitor, daemon=True).start()

        else:
            # Désactiver le mode moniteur
            self.wifi_status_var.set("Désactivation du mode moniteur...")

            def deactivate_monitor():
                success = self.wifi_scanner.disable_monitor_mode(self.wifi_monitor_interface)

                if success:
                    self.wifi_monitor_mode_active = False
                    self.wifi_monitor_interface = None

                    self.root.after(0, lambda: self.btn_monitor_mode.config(
                        text="📡 Activer Mode Moniteur",
                        bootstyle="success"
                    ))
                    self.root.after(0, lambda: self.btn_scan_wifi.config(state=DISABLED))
                    self.root.after(0, lambda: self.btn_capture_handshake.config(state=DISABLED))
                    self.root.after(0, lambda: self.wifi_monitor_status_var.set(
                        "Mode moniteur: Inactif"
                    ))
                    self.root.after(0, lambda: self.wifi_status_var.set(
                        "Mode moniteur désactivé"
                    ))

            threading.Thread(target=deactivate_monitor, daemon=True).start()

    def _scan_wifi_networks(self):
        """Lance le scan des réseaux WiFi"""
        if not self.wifi_scanner or not self.wifi_monitor_interface:
            return

        self.btn_scan_wifi.config(state=DISABLED)
        self.wifi_status_var.set("Scan des réseaux WiFi en cours...")
        self.wifi_progress['value'] = 0

        def scan_worker():
            try:
                networks = self.wifi_scanner.scan_networks_airodump(
                    self.wifi_monitor_interface,
                    duration=30
                )

                self.wifi_networks = networks

                # Afficher les résultats
                self.root.after(0, lambda: self._display_wifi_networks(networks))

            except Exception as e:
                logger.error(f"Erreur scan WiFi: {e}")
                self.root.after(0, lambda: self.wifi_status_var.set(f"Erreur: {e}"))
                self.root.after(0, lambda: messagebox.showerror(
                    "Erreur",
                    f"Erreur lors du scan WiFi:\n{e}"
                ))
            finally:
                self.root.after(0, lambda: self.btn_scan_wifi.config(state=NORMAL))
                self.root.after(0, lambda: self.wifi_progress.config(value=0))

        threading.Thread(target=scan_worker, daemon=True).start()

    def _display_wifi_networks(self, networks):
        """Affiche les réseaux WiFi dans la table"""
        # Vider la table
        for item in self.wifi_tree.get_children():
            self.wifi_tree.delete(item)

        # Trier par puissance du signal
        networks.sort(key=lambda x: x.signal_strength, reverse=True)

        # Ajouter les réseaux
        for i, network in enumerate(networks, 1):
            # Icône selon le signal
            if network.signal_strength > -50:
                signal_icon = "📶"
            elif network.signal_strength > -60:
                signal_icon = "📶"
            elif network.signal_strength > -70:
                signal_icon = "📡"
            else:
                signal_icon = "📡"

            # Tag pour coloration selon chiffrement
            tag = "wpa" if "WPA" in network.encryption else "open" if "Open" in network.encryption else ""

            self.wifi_tree.insert('', tk.END, text=str(i), values=(
                network.ssid if network.ssid else "<Hidden>",
                network.bssid,
                network.channel,
                network.encryption,
                f"{signal_icon} {network.signal_strength}",
                len(network.clients)
            ), tags=(tag,))

        # Configuration des tags
        self.wifi_tree.tag_configure("wpa", foreground="green")
        self.wifi_tree.tag_configure("open", foreground="red")

        # Activer le bouton de capture
        if networks:
            self.btn_capture_handshake.config(state=NORMAL)

        # Mettre à jour le compteur
        self.wifi_count_var.set(f"Réseaux trouvés: {len(networks)}")
        self.wifi_status_var.set(f"Scan terminé - {len(networks)} réseau(x) détecté(s)")

        # Message de succès
        wpa_count = sum(1 for n in networks if "WPA" in n.encryption)
        messagebox.showinfo(
            "Scan terminé",
            f"Scan WiFi terminé!\n\n"
            f"• Réseaux détectés: {len(networks)}\n"
            f"• Réseaux WPA/WPA2: {wpa_count}\n\n"
            "Sélectionnez un réseau WPA pour capturer le handshake."
        )

    def _capture_selected_handshake(self):
        """Capture le handshake du réseau sélectionné"""
        selection = self.wifi_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Sélectionnez un réseau WiFi")
            return

        item = self.wifi_tree.item(selection[0])
        values = item['values']

        ssid = values[0]
        bssid = values[1]
        channel = values[2]
        encryption = values[3]

        # Vérifier que c'est un réseau WPA
        if "WPA" not in encryption:
            messagebox.showwarning(
                "Réseau non compatible",
                f"Le réseau {ssid} utilise le chiffrement {encryption}.\n\n"
                "La capture de handshake fonctionne uniquement avec WPA/WPA2/WPA3."
            )
            return

        # Demander confirmation
        result = messagebox.askyesno(
            "Capture de handshake",
            f"Capturer le handshake pour:\n\n"
            f"SSID: {ssid}\n"
            f"BSSID: {bssid}\n"
            f"Canal: {channel}\n"
            f"Chiffrement: {encryption}\n\n"
            f"Durée: 60 secondes\n\n"
            f"⚠️ IMPORTANT:\n"
            f"• Utilisez uniquement sur VOS propres réseaux\n"
            f"• L'utilisation sans autorisation est ILLÉGALE\n\n"
            f"Avez-vous l'autorisation pour ce réseau?"
        )

        if not result:
            return

        # Lancer la capture
        self.btn_capture_handshake.config(state=DISABLED)
        self.wifi_status_var.set(f"Capture du handshake pour {ssid}...")
        self.wifi_progress['value'] = 0

        def capture_worker():
            output_file = f"/tmp/handshake_{bssid.replace(':', '')}.pcap"

            try:
                # Afficher la progression
                for i in range(0, 101, 10):
                    self.root.after(0, lambda v=i: self.wifi_progress.config(value=v))
                    if i < 100:
                        import time
                        time.sleep(6)  # 60 secondes total

                success = self.wifi_scanner.capture_handshake_scapy(
                    bssid=bssid,
                    channel=int(channel),
                    interface=self.wifi_monitor_interface,
                    duration=60,
                    output_file=output_file
                )

                if success:
                    # Essayer d'extraire le hash
                    hash_result = self.wifi_scanner.extract_hash_from_pcap(output_file)

                    message = f"✓ Handshake capturé avec succès!\n\n"
                    message += f"SSID: {ssid}\n"
                    message += f"BSSID: {bssid}\n\n"
                    message += f"Fichier PCAP: {output_file}\n\n"

                    if hash_result:
                        if hash_result.endswith('.hc22000'):
                            message += f"Hash extrait: {hash_result}\n\n"
                            message += "Commande pour cracker (hashcat):\n"
                            message += f"hashcat -m 22000 {hash_result} wordlist.txt\n\n"
                        else:
                            message += "Commande pour cracker (aircrack-ng):\n"
                            message += f"aircrack-ng -w wordlist.txt {output_file}\n\n"

                        message += "Ou convertir pour hashcat:\n"
                        message += f"hcxpcapngtool -o hash.hc22000 {output_file}"

                    self.root.after(0, lambda: self.wifi_status_var.set(
                        f"Handshake capturé: {ssid}"
                    ))
                    self.root.after(0, lambda: messagebox.showinfo("Succès", message))

                else:
                    self.root.after(0, lambda: self.wifi_status_var.set(
                        f"Handshake non capturé: {ssid}"
                    ))
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Échec",
                        f"Handshake non capturé pour {ssid}\n\n"
                        "Raisons possibles:\n"
                        "• Aucun client connecté au réseau\n"
                        "• Aucune reconnexion pendant la capture\n"
                        "• Signal trop faible\n\n"
                        "Solutions:\n"
                        "• Augmentez la durée de capture\n"
                        "• Déconnectez manuellement un appareil\n"
                        "• Rapprochez-vous du point d'accès"
                    ))

            except Exception as e:
                logger.error(f"Erreur capture handshake: {e}")
                self.root.after(0, lambda: self.wifi_status_var.set(f"Erreur: {e}"))
                self.root.after(0, lambda: messagebox.showerror(
                    "Erreur",
                    f"Erreur lors de la capture:\n{e}"
                ))
            finally:
                self.root.after(0, lambda: self.btn_capture_handshake.config(state=NORMAL))
                self.root.after(0, lambda: self.wifi_progress.config(value=0))

        threading.Thread(target=capture_worker, daemon=True).start()

    def _update_wifi_progress(self, message, progress):
        """Callback pour les mises à jour du scanner WiFi"""
        self.root.after(0, lambda: self.wifi_status_var.set(message))
        self.root.after(0, lambda: self.wifi_progress.config(value=progress))
        logger.info(f"WiFi: {message}")

    def _copy_wifi_ssid(self):
        """Copie le SSID sélectionné dans le presse-papiers"""
        selection = self.wifi_tree.selection()
        if selection:
            item = self.wifi_tree.item(selection[0])
            ssid = item['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ssid)
            self.wifi_status_var.set(f"SSID copié: {ssid}")

    def _copy_wifi_bssid(self):
        """Copie le BSSID sélectionné dans le presse-papiers"""
        selection = self.wifi_tree.selection()
        if selection:
            item = self.wifi_tree.item(selection[0])
            bssid = item['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(bssid)
            self.wifi_status_var.set(f"BSSID copié: {bssid}")

    def _show_wifi_context_menu(self, event):
        """Affiche le menu contextuel WiFi"""
        # Sélectionner l'élément sous le curseur
        item = self.wifi_tree.identify_row(event.y)
        if item:
            self.wifi_tree.selection_set(item)
            self.wifi_tree_menu.post(event.x_root, event.y_root)

    def _clear_wifi_results(self):
        """Efface les résultats WiFi"""
        for item in self.wifi_tree.get_children():
            self.wifi_tree.delete(item)
        self.wifi_networks = []
        self.wifi_count_var.set("Réseaux trouvés: 0")
        self.wifi_status_var.set("Résultats effacés")

    def _show_wifi_instructions(self):
        """Affiche les instructions d'installation et d'utilisation WiFi"""
        if not self.wifi_scanner:
            instructions = """
MODULE WIFI SCANNER NON DISPONIBLE
===================================

Le module wifi_scanner.py n'est pas accessible.

Installation:
1. Vérifiez que wifi_scanner.py est dans le répertoire du projet
2. Installez les dépendances:
   sudo apt-get install aircrack-ng hcxtools
3. Relancez l'application avec sudo:
   sudo python3 main.py
"""
        else:
            instructions = self.wifi_scanner.get_installation_instructions()

        # Créer une fenêtre pour afficher les instructions
        instructions_window = tk.Toplevel(self.root)
        instructions_window.title("Instructions WiFi Scanner")
        instructions_window.geometry("800x600")

        text = scrolledtext.ScrolledText(
            instructions_window,
            wrap=tk.WORD,
            font=("Courier New", 10),
            padx=10,
            pady=10
        )
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, instructions)
        text.config(state=tk.DISABLED)

        ttk.Button(
            instructions_window,
            text="Fermer",
            command=instructions_window.destroy,
            bootstyle="secondary"
        ).pack(pady=10)

    # ========================================================================
    # FIN DES FONCTIONS WIFI
    # ========================================================================

    def _quit_application(self):
        """
        Quitte l'application proprement
        """
        # Vérifier si un scan est en cours
        if self.scan_thread and self.scan_thread.is_alive():
            response = messagebox.askyesno(
                "Scan en cours",
                "Un scan est actuellement en cours.\n\nVoulez-vous vraiment quitter?"
            )
            if not response:
                return

        # Désactiver le mode moniteur WiFi si actif
        if self.wifi_monitor_mode_active and self.wifi_scanner:
            try:
                self.wifi_scanner.disable_monitor_mode(self.wifi_monitor_interface)
                logger.info("Mode moniteur WiFi désactivé avant fermeture")
            except Exception as e:
                logger.error(f"Erreur désactivation mode moniteur: {e}")

        # Arrêter le scan si en cours
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.cancel()
            self.root.after(500, self.root.destroy)
        else:
            # Quitter directement
            self.root.destroy()


def run():
    """
    Lance l'application avec thème moderne ttkbootstrap
    """
    # Charger le thème sauvegardé ou utiliser le thème par défaut
    default_theme = "simplex"
    theme_config_file = Path("theme_config.json")

    if theme_config_file.exists():
        try:
            import json
            with open(theme_config_file, 'r') as f:
                config = json.load(f)
                saved_theme = config.get("theme", default_theme)
        except Exception:
            saved_theme = default_theme
    else:
        saved_theme = default_theme

    # Créer la fenêtre avec le thème chargé
    # Autres thèmes disponibles: flatly, litera, minty, lumen, sandstone, yeti, pulse, united, morph, journal, darkly, superhero, solar, cyborg, vapor, simplex, cerculean
    root = ttk.Window(
        title="🔍 Scanner IP Local",
        themename=saved_theme,
        size=(1500, 900),
        resizable=(True, True)
    )

    app = MainWindow(root)

    # Gérer la fermeture de la fenêtre par le X
    root.protocol("WM_DELETE_WINDOW", app._quit_application)

    # Centrer la fenêtre
    root.place_window_center()

    root.mainloop()
