#!/usr/bin/env python3
"""
Test de détection d'appareils via MAC
"""

from mac_vendors import get_vendor_from_mac, MAC_VENDORS

# Afficher tous les préfixes Google
print("=" * 60)
print("PRÉFIXES MAC GOOGLE/PIXEL DANS LA BASE")
print("=" * 60)
for mac_prefix, vendor in MAC_VENDORS.items():
    if "Google" in vendor or "Pixel" in vendor:
        print(f"{mac_prefix} → {vendor}")

print("\n" + "=" * 60)
print("TEST DE DÉTECTION")
print("=" * 60)

# Tester quelques MAC
test_macs = [
    "B4:CE:F6:12:34:56",  # Google Pixel
    "D8:3B:BF:AA:BB:CC",  # Google Pixel
    "94:EB:CD:11:22:33",  # Google Pixel
    "A4:B1:97:44:55:66",  # iPhone
]

for mac in test_macs:
    vendor, device_type = get_vendor_from_mac(mac)
    print(f"\n{mac}")
    print(f"  → Fabricant: {vendor if vendor else 'Inconnu'}")
    print(f"  → Type: {device_type if device_type else 'Inconnu'}")

print("\n" + "=" * 60)
print("ENTREZ VOTRE ADRESSE MAC POUR TESTER")
print("=" * 60)

mac_input = input("\nAdresse MAC de votre Pixel (format AA:BB:CC:DD:EE:FF): ").strip()

if mac_input:
    vendor, device_type = get_vendor_from_mac(mac_input)

    print(f"\nRésultat:")
    print(f"  MAC: {mac_input}")
    print(f"  Fabricant: {vendor if vendor else '❌ NON TROUVÉ'}")
    print(f"  Type: {device_type if device_type else '❌ NON DÉTECTÉ'}")

    if not vendor:
        oui = ":".join(mac_input.upper().split(":")[:3])
        print(f"\n⚠️  Le préfixe {oui} n'est pas dans la base de données")
        print(f"    Ajoutez cette ligne dans mac_vendors.py:")
        print(f'    "{oui}": "Google (Pixel)",')
