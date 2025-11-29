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

        # Variables
        self.scan_thread = None
        self.current_results = []
        self.scan_start_time = None
        self.has_root = is_root()

        # Historique
        self.history_file = HISTORY_DIR / "scan_history.json"
        self.scan_history = self._load_history()

        # Configuration de la fenêtre
        self._create_widgets()
        self._check_root_privileges()

    def _create_widgets(self):
        """
        Crée tous les widgets avec design moderne ttkbootstrap
        """
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.grid(row=0, column=0, sticky=(W, E, N, S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # En-tête moderne avec carte
        header_frame = ttk.Frame(main_frame, bootstyle="dark")
        header_frame.grid(row=0, column=0, pady=(0, 20), sticky=(W, E), ipady=15, ipadx=15)
        header_frame.columnconfigure(0, weight=1)

        # Titre avec icône
        title_label = ttk.Label(
            header_frame,
            text="🔍 Scanner IP Local",
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

        # Frame de configuration
        self._create_config_frame(main_frame)

        # Frame de contrôle
        self._create_control_frame(main_frame)

        # Frame de résultats
        self._create_results_frame(main_frame)

        # Frame de statut
        self._create_status_frame(main_frame)

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

        # Bouton Démarrer (vert, grand)
        self.btn_scan = ttk.Button(
            control_frame,
            text="▶  Démarrer le Scan",
            command=self._start_scan,
            bootstyle="success",
            width=20
        )
        self.btn_scan.pack(side=LEFT, padx=5)

        # Bouton Arrêter (rouge)
        self.btn_stop = ttk.Button(
            control_frame,
            text="⏹  Arrêter",
            command=self._stop_scan,
            state=DISABLED,
            bootstyle="danger",
            width=15
        )
        self.btn_stop.pack(side=LEFT, padx=5)

        # Séparateur visuel
        ttk.Separator(control_frame, orient=VERTICAL).pack(side=LEFT, fill=Y, padx=10)

        # Bouton Exporter (bleu)
        ttk.Button(
            control_frame,
            text="💾  Exporter",
            command=self._export_results,
            bootstyle="info",
            width=15
        ).pack(side=LEFT, padx=5)

        # Bouton Effacer
        ttk.Button(
            control_frame,
            text="🗑  Effacer",
            command=self._clear_results,
            bootstyle="secondary-outline",
            width=12
        ).pack(side=LEFT, padx=5)

        # Bouton Historique
        ttk.Button(
            control_frame,
            text="📜  Historique",
            command=self._show_history,
            bootstyle="secondary-outline",
            width=14
        ).pack(side=LEFT, padx=5)

        # Séparateur visuel
        ttk.Separator(control_frame, orient=VERTICAL).pack(side=LEFT, fill=Y, padx=10)

        # Bouton Scan Vulnérabilités (rouge/orange)
        self.btn_vuln_scan = ttk.Button(
            control_frame,
            text="🔒  Scan Vulnérabilités",
            command=self._scan_vulnerabilities,
            bootstyle="warning",
            width=20
        )
        self.btn_vuln_scan.pack(side=LEFT, padx=5)

        # BOUTON QUITTER (rouge, à droite)
        ttk.Button(
            control_frame,
            text="✖  Quitter",
            command=self._quit_application,
            bootstyle="danger-outline",
            width=12
        ).pack(side=RIGHT, padx=5)

        # BOUTON THÈMES (à droite, avant quitter)
        ttk.Button(
            control_frame,
            text="🎨  Thèmes",
            command=self._show_theme_selector,
            bootstyle="info-outline",
            width=12
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

        column_widths = {'IP': 120, 'Hostname': 200, 'MAC': 150, 'OS': 120, 'Temps (ms)': 100, 'Ports': 200, 'Vulnérabilités': 200}

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
                "- Détection OS avancée\n\n"
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

        # Fenêtre de détails
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Détails - {ip}")
        details_window.geometry("600x500")
        details_window.transient(self.root)

        # Zone de texte
        text = scrolledtext.ScrolledText(details_window, wrap=WORD, font=('Courier', 10))
        text.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Afficher les détails
        response_time_detail = f"{result.get('response_time', 0):.0f}" if result.get('response_time') else 'N/A'
        details = f"""
INFORMATIONS DE L'HÔTE
{'=' * 50}

Adresse IP:       {result['ip']}
Nom d'hôte:       {result['hostname']}
Adresse MAC:      {result['mac']}
Système:          {result.get('os', 'Unknown')}
Statut:           {result['status'].upper()}
Temps de réponse: {response_time_detail} ms

"""

        if result.get('open_ports'):
            details += f"\nPORTS OUVERTS ({len(result['open_ports'])}):\n"
            details += "=" * 50 + "\n\n"

            for port_info in result['open_ports']:
                details += f"Port {port_info['port']:5d} - {port_info['service']:20s} [{port_info['status']}]\n"

                if port_info.get('banner'):
                    banner = port_info['banner'][:100]
                    details += f"  Banner: {banner}\n"

                details += "\n"
        else:
            details += "\nAucun port ouvert détecté\n"

        # Afficher les vulnérabilités
        if result.get('vulnerabilities'):
            vulnerabilities = result['vulnerabilities']
            details += f"\n\nVULNÉRABILITÉS DÉTECTÉES ({len(vulnerabilities)}):\n"
            details += "=" * 50 + "\n\n"

            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'INCONNU')
                cvss = vuln.get('cvss_score', 'N/A')
                cve_id = vuln.get('cve_id', 'N/A')
                port = vuln.get('port', 'N/A')
                service = vuln.get('service', 'N/A')
                description = vuln.get('description', 'Aucune description')

                # Emoji selon criticité
                emoji = {
                    'CRITIQUE': '🔴',
                    'ÉLEVÉ': '🟠',
                    'MOYEN': '🟡',
                    'FAIBLE': '🟢',
                    'INCONNU': '⚪'
                }.get(severity, '⚪')

                details += f"{emoji} {severity} - CVSS: {cvss}\n"
                details += f"CVE ID:      {cve_id}\n"
                details += f"Port:        {port} ({service})\n"
                details += f"Description: {description[:200]}\n"
                details += "-" * 50 + "\n\n"

        elif result.get('vulnerabilities_summary') == 'Aucune':
            details += "\n\n✅ Aucune vulnérabilité détectée\n"
        elif result.get('vuln_error'):
            details += f"\n\n⚠️ Erreur lors du scan de vulnérabilités:\n{result['vuln_error']}\n"
        else:
            details += "\n\n⚠️ Scan de vulnérabilités non effectué\n"
            details += "Cliquez sur 'Scan Vulnérabilités' pour analyser les vulnérabilités.\n"

        text.insert(1.0, details)
        text.config(state=DISABLED)

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

        # Confirmation
        response = messagebox.askyesno(
            "Scan de vulnérabilités",
            f"Scanner {len(self.current_results)} hôte(s) avec {method.upper()}?\n\n"
            "⚠️ Cela peut prendre plusieurs minutes par hôte.\n\n"
            "Continuer?"
        )

        if not response:
            return

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
            if response:
                # Arrêter le scan
                self.scan_thread.cancel()
                self.root.after(500, self.root.destroy)
        else:
            # Quitter directement sans confirmation
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
