"""
Thread pour exécuter les scans sans bloquer l'interface
"""

import threading
import queue
from typing import Dict, List, Callable
import logging

from scanner import IPScanner

logger = logging.getLogger(__name__)


class ScanThread(threading.Thread):
    """
    Thread pour exécuter un scan réseau de manière asynchrone
    """

    def __init__(
        self,
        network: str,
        scan_config: Dict,
        result_callback: Callable = None,
        progress_callback: Callable = None
    ):
        """
        Initialise le thread de scan

        Args:
            network: Plage réseau à scanner
            scan_config: Configuration du scan
            result_callback: Callback appelé avec les résultats finaux
            progress_callback: Callback appelé pour les mises à jour de progression
        """
        super().__init__()
        self.network = network
        self.scan_config = scan_config
        self.result_callback = result_callback
        self.progress_callback = progress_callback

        self.scanner = IPScanner(callback=self._on_progress)
        self.results = []
        self.is_cancelled = False
        self.daemon = True

    def _on_progress(self, message: str, progress: int):
        """
        Gestionnaire de progression du scanner

        Args:
            message: Message de progression
            progress: Pourcentage (0-100)
        """
        if self.progress_callback:
            self.progress_callback(message, progress)

    def run(self):
        """
        Exécute le scan
        """
        try:
            logger.info(f"Démarrage du scan: {self.network}")
            self.results = self.scanner.scan_network(self.network, self.scan_config)

            if not self.is_cancelled and self.result_callback:
                self.result_callback(self.results)

            logger.info(f"Scan terminé: {len(self.results)} hôtes trouvés")

        except Exception as e:
            logger.error(f"Erreur durant le scan: {e}")
            if self.progress_callback:
                self.progress_callback(f"Erreur: {e}", -1)

    def cancel(self):
        """
        Annule le scan en cours
        """
        logger.info("Annulation du scan demandée")
        self.is_cancelled = True
        self.scanner.stop_scan()
