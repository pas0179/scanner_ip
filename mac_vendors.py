"""
Base de données des préfixes MAC (OUI - Organizationally Unique Identifier)
pour identifier les fabricants d'appareils
"""

# Préfixes MAC des fabricants courants (3 premiers octets)
MAC_VENDORS = {
    # Google/Android
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    "AC:37:43": "Google",
    "B4:CE:F6": "Google (Pixel)",
    "74:E5:43": "Google (Nexus)",
    "F8:8F:CA": "Google",
    "D8:3B:BF": "Google (Pixel)",
    "94:EB:CD": "Google (Pixel)",
    "56:E3:B7": "Google (Pixel)",

    # Apple/iOS
    "00:03:93": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "A4:B1:97": "Apple (iPhone)",
    "A4:D1:D2": "Apple (iPhone)",
    "BC:92:6B": "Apple (iPhone)",
    "C8:2A:14": "Apple (iPhone)",
    "D8:30:62": "Apple (iPad)",
    "DC:2B:61": "Apple (MacBook)",
    "F0:DB:E2": "Apple (iPhone)",

    # Samsung
    "00:00:F0": "Samsung",
    "00:12:FB": "Samsung",
    "00:15:B9": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:17:C9": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1E:7D": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:4C": "Samsung",
    "00:23:39": "Samsung",
    "00:23:D6": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:E9": "Samsung (Galaxy)",
    "00:25:38": "Samsung",
    "00:26:37": "Samsung",
    "E8:50:8B": "Samsung (Galaxy)",
    "34:23:BA": "Samsung (Galaxy)",
    "F4:7B:5E": "Samsung (Galaxy)",

    # Xiaomi
    "50:8F:4C": "Xiaomi",
    "64:09:80": "Xiaomi",
    "78:02:F8": "Xiaomi",
    "8C:BE:BE": "Xiaomi",
    "A0:86:C6": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    "34:CE:00": "Xiaomi",

    # Huawei
    "00:1E:10": "Huawei",
    "00:25:9E": "Huawei",
    "00:46:4B": "Huawei",
    "00:66:4B": "Huawei",
    "00:E0:FC": "Huawei",
    "48:7D:2E": "Huawei",
    "AC:85:3D": "Huawei",

    # Routeurs courants
    "00:14:BF": "TP-Link",
    "00:25:86": "TP-Link",
    "50:C7:BF": "TP-Link",
    "E8:94:F6": "TP-Link",
    "00:0C:42": "Cisco",
    "00:1B:D5": "Cisco",
    "00:1D:45": "D-Link",
    "00:1B:11": "D-Link",
    "B0:B9:8A": "Netgear",
    "A0:21:B7": "Netgear",
    "00:24:01": "AsusTek",
    "00:1D:60": "AsusTek",

    # Windows/PC
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "08:00:27": "VirtualBox",
}

# Patterns pour détecter les types d'appareils
DEVICE_PATTERNS = {
    "Google (Pixel)": "Android (Pixel)",
    "Google (Nexus)": "Android (Nexus)",
    "Google": "Android (Google)",
    "Apple (iPhone)": "iOS (iPhone)",
    "Apple (iPad)": "iOS (iPad)",
    "Apple (MacBook)": "macOS",
    "Apple": "iOS/macOS",
    "Samsung (Galaxy)": "Android (Samsung)",
    "Samsung": "Android (Samsung)",
    "Xiaomi": "Android (Xiaomi)",
    "Huawei": "Android (Huawei)",
    "TP-Link": "Router",
    "Cisco": "Router/Switch",
    "D-Link": "Router",
    "Netgear": "Router",
    "AsusTek": "Router/PC",
    "VMware": "Virtual Machine",
    "VirtualBox": "Virtual Machine",
}


def get_vendor_from_mac(mac_address):
    """
    Récupère le fabricant à partir de l'adresse MAC

    Args:
        mac_address: Adresse MAC (format: AA:BB:CC:DD:EE:FF)

    Returns:
        Tuple (vendor, device_type) ou (None, None)
    """
    if not mac_address or mac_address == "N/A":
        return None, None

    # Extraire les 3 premiers octets (OUI)
    mac_parts = mac_address.upper().replace("-", ":").split(":")
    if len(mac_parts) >= 3:
        oui = ":".join(mac_parts[:3])

        vendor = MAC_VENDORS.get(oui)
        if vendor:
            device_type = DEVICE_PATTERNS.get(vendor, "Unknown")
            return vendor, device_type

    return None, None


def detect_device_type(mac_address, ttl_os):
    """
    Détecte le type d'appareil en combinant MAC et TTL

    Args:
        mac_address: Adresse MAC
        ttl_os: OS détecté via TTL

    Returns:
        Type d'appareil détecté
    """
    vendor, device_type = get_vendor_from_mac(mac_address)

    if device_type and device_type != "Unknown":
        return device_type

    # Si on a un fabricant mais pas de type précis
    if vendor:
        if "Google" in vendor or "Pixel" in vendor:
            return "Android (Google)"
        elif "Samsung" in vendor:
            return "Android (Samsung)"
        elif "Apple" in vendor:
            return "iOS/macOS (Apple)"
        elif "Xiaomi" in vendor or "Huawei" in vendor:
            return "Android"
        elif any(x in vendor for x in ["Router", "Cisco", "TP-Link", "D-Link", "Netgear"]):
            return "Router/Network Device"
        elif "VM" in vendor or "Virtual" in vendor:
            return "Virtual Machine"
        else:
            return f"{vendor} Device"

    # Fallback sur la détection TTL
    return ttl_os
