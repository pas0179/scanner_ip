#!/usr/bin/env python3
"""
Utilitaire pour choisir et tester différents thèmes ttkbootstrap
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk

def preview_themes():
    """
    Affiche une fenêtre permettant de tester tous les thèmes disponibles
    """

    # Thèmes disponibles avec descriptions
    themes = {
        "cosmo": "Moderne et élégant (recommandé)",
        "flatly": "Plat et minimaliste",
        "litera": "Classique et lisible",
        "minty": "Vert menthe frais",
        "lumen": "Lumineux et spacieux",
        "sandstone": "Terre et naturel",
        "yeti": "Neutre et professionnel",
        "pulse": "Vibrant et énergique",
        "united": "Corporate et sérieux",
        "morph": "Doux et arrondi",
        "journal": "Style journal/blog",
        "darkly": "Sombre et moderne",
        "superhero": "Sombre avec accents bleus",
        "solar": "Sombre ambré",
        "cyborg": "Sombre cyberpunk",
        "vapor": "Rétro vaporwave",
        "simplex": "Simple et épuré",
        "cerculean": "Bleu professionnel"
    }

    def change_theme():
        """Change le thème de l'application"""
        selected = theme_var.get()
        root.style.theme_use(selected)
        status_label.config(text=f"Thème actuel: {selected} - {themes[selected]}")

    def apply_and_save():
        """Applique le thème et met à jour gui.py"""
        selected = theme_var.get()

        # Lire gui.py
        with open('gui.py', 'r', encoding='utf-8') as f:
            content = f.read()

        # Remplacer le thème
        import re
        new_content = re.sub(
            r'themename="[^"]*"',
            f'themename="{selected}"',
            content
        )

        # Sauvegarder
        with open('gui.py', 'w', encoding='utf-8') as f:
            f.write(new_content)

        result_label.config(
            text=f"✓ Thème '{selected}' appliqué et sauvegardé dans gui.py!",
            bootstyle="success"
        )

    # Créer la fenêtre
    root = ttk.Window(
        title="Choisir le thème - Scanner IP",
        themename="cosmo",
        size=(700, 600)
    )

    # Titre
    ttk.Label(
        root,
        text="🎨 Choisir le thème du Scanner IP",
        font=("Segoe UI", 18, "bold"),
        bootstyle="primary"
    ).pack(pady=20)

    # Description
    ttk.Label(
        root,
        text="Sélectionnez un thème et cliquez sur 'Appliquer' pour le tester.\nCliquez sur 'Sauvegarder' pour l'appliquer définitivement.",
        font=("Segoe UI", 10)
    ).pack(pady=10)

    # Frame pour la sélection
    select_frame = ttk.Labelframe(root, text="Thèmes disponibles", padding=20)
    select_frame.pack(pady=20, padx=20, fill=BOTH, expand=YES)

    # Variable pour le thème sélectionné
    theme_var = tk.StringVar(value="cosmo")

    # Créer les boutons radio pour chaque thème
    for theme, description in themes.items():
        ttk.Radiobutton(
            select_frame,
            text=f"{theme:15} - {description}",
            variable=theme_var,
            value=theme,
            bootstyle="primary-toolbutton"
        ).pack(anchor=W, pady=2)

    # Frame pour les boutons
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=20)

    ttk.Button(
        button_frame,
        text="Appliquer (tester)",
        command=change_theme,
        bootstyle="info",
        width=20
    ).pack(side=LEFT, padx=10)

    ttk.Button(
        button_frame,
        text="Sauvegarder dans gui.py",
        command=apply_and_save,
        bootstyle="success",
        width=25
    ).pack(side=LEFT, padx=10)

    # Label de statut
    status_label = ttk.Label(
        root,
        text="Thème actuel: cosmo - Moderne et élégant",
        font=("Segoe UI", 10, "bold"),
        bootstyle="info"
    )
    status_label.pack(pady=10)

    # Label de résultat
    result_label = ttk.Label(
        root,
        text="",
        font=("Segoe UI", 10)
    )
    result_label.pack(pady=5)

    # Info
    info_frame = ttk.Labelframe(root, text="Aperçu des boutons", padding=10)
    info_frame.pack(pady=10, padx=20, fill=X)

    preview_frame = ttk.Frame(info_frame)
    preview_frame.pack()

    ttk.Button(preview_frame, text="Success", bootstyle="success").pack(side=LEFT, padx=5)
    ttk.Button(preview_frame, text="Danger", bootstyle="danger").pack(side=LEFT, padx=5)
    ttk.Button(preview_frame, text="Info", bootstyle="info").pack(side=LEFT, padx=5)
    ttk.Button(preview_frame, text="Warning", bootstyle="warning").pack(side=LEFT, padx=5)
    ttk.Button(preview_frame, text="Secondary", bootstyle="secondary").pack(side=LEFT, padx=5)

    # Centrer la fenêtre
    root.place_window_center()

    root.mainloop()


if __name__ == "__main__":
    print("=" * 60)
    print("SÉLECTEUR DE THÈME - Scanner IP Local")
    print("=" * 60)
    print("\nLancement de l'interface de sélection de thème...")
    print("Choisissez votre thème préféré et appliquez-le!\n")

    preview_themes()
