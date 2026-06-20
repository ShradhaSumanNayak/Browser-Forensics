import json
from pathlib import Path

class ExtensionsParser:
    """
    Parses installed extensions/add-ons and their permissions from browser metadata files.
    """
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.file_path.name.lower()
        if "chrome" in name or "edge" in name or "brave" in name or "opera" in name or "preferences" in name:
            return "chrome_edge"
        elif "firefox" in name or "tor" in name or "addons" in name:
            return "firefox"
        return "unknown"

    def _browser_label(self):
        name = self.file_path.name.lower()
        if "chrome" in name:
            return "Chrome"
        if "edge" in name:
            return "Edge"
        if "brave" in name:
            return "Brave"
        if "opera" in name:
            return "Opera"
        if "tor" in name:
            return "Tor"
        if "firefox" in name:
            return "Firefox"
        return "Unknown"

    def parse(self):
        if not self.file_path.exists():
            return []

        results = []
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if not content:
                    return []
                data = json.loads(content)

            if self.browser_type == "chrome_edge":
                # Check both Preferences and Secure Preferences structure
                # Sometimes it's in 'extensions' -> 'settings', sometimes 'op_settings'
                ext_root = data.get("extensions", {})
                extensions = ext_root.get("settings", {})
                if not extensions:
                    extensions = ext_root.get("op_settings", {})
                
                if not extensions and "extensions" in data:
                    # If it's a flatter structure or Secure Preferences variation
                    if isinstance(data.get("extensions"), dict):
                        extensions = data.get("extensions")

                for ext_id, ext_data in extensions.items():
                    if not isinstance(ext_data, dict):
                        continue
                    
                    manifest = ext_data.get("manifest", {})
                    name = manifest.get("name", ext_id)
                    version = manifest.get("version", "Unknown")
                    permissions = manifest.get("permissions", [])
                    install_time = ext_data.get("install_time", "")
                    
                    # Fix for internal names (e.g. __MSG_extension_name__)
                    if name.startswith("__MSG_") and "name" in ext_data:
                        name = ext_data.get("name")

                    results.append({
                        "Browser": self._browser_label(),
                        "Extension ID": ext_id,
                        "Name": name,
                        "Version": version,
                        "Permissions": ", ".join([str(p) for p in permissions]) if isinstance(permissions, list) else str(permissions),
                        "Install Time": install_time,
                        "Enabled": "Yes" if ext_data.get("state") == 1 else "No"
                    })

            elif self.browser_type == "firefox":
                # Firefox addons.json
                addons = data.get("addons", [])
                for addon in addons:
                    results.append({
                        "Browser": self._browser_label(),
                        "Extension ID": addon.get("id", ""),
                        "Name": addon.get("defaultLocale", {}).get("name", addon.get("name", "Unknown")),
                        "Version": addon.get("version", "Unknown"),
                        "Permissions": ", ".join(addon.get("permissions", [])) if isinstance(addon.get("permissions"), list) else "N/A",
                        "Install Time": addon.get("installDate", ""),
                        "Enabled": "Yes" if addon.get("active") else "No"
                    })

        except Exception as e:
            print(f"[-] Error parsing extensions from {self.file_path}: {e}")

        print(f"[+] Parsed {len(results)} extensions from {self.file_path.name}.")
        return results
