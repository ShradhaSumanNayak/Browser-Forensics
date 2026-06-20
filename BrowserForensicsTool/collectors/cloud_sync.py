import os
import platform
from pathlib import Path
from utils.hasher import generate_sha256, write_hash_manifest
from utils.io_helper import copy_resilient

class CloudSyncCollector:
    """
    Locates and extracts artifacts related to browser cloud synchronization.
    These files often contain cached copies of history, tabs, and preferences
    synced across devices.
    """
    def __init__(self, output_dir, source_root=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.source_root = Path(source_root) if source_root else None

    def _identity_from_path(self, path):
        parts = list(Path(path).parts)
        lowered = [part.lower() for part in parts]

        owner = "unknown"
        if "users" in lowered:
            idx = lowered.index("users")
            if idx + 1 < len(parts):
                owner = parts[idx + 1]
        elif "home" in lowered:
            idx = lowered.index("home")
            if idx + 1 < len(parts):
                owner = parts[idx + 1]
        elif len(parts) >= 2:
            owner = parts[-2]

        safe = "".join(char.lower() if char.isalnum() else "_" for char in f"{owner}_{Path(path).name}")
        while "__" in safe:
            safe = safe.replace("__", "_")
        return safe.strip("_")
        
    def collect(self):
        print("\n[*] Starting Cloud Sync Artifact Collection...")
        success_count = 0
        file_hashes = {}
        
        # Define paths for major browsers
        user_home = Path.home()
        system = platform.system()
        
        sync_targets = []
        
        if self.source_root:
            for browser_name, pattern in [
                ("Chrome", "Users/*/AppData/Local/Google/Chrome/User Data"),
                ("Edge", "Users/*/AppData/Local/Microsoft/Edge/User Data"),
                ("Chrome", "home/*/.config/google-chrome"),
                ("Edge", "home/*/.config/microsoft-edge"),
                ("Chrome", "Users/*/Library/Application Support/Google/Chrome"),
            ]:
                for app_dir in self.source_root.glob(pattern):
                    profiles = [app_dir / "Default"] + list(app_dir.glob("Profile *"))
                    for profile in profiles:
                        sync_file = profile / "Sync Data"
                        if sync_file.exists():
                            p_name = self._identity_from_path(profile)
                            sync_targets.append({
                                "browser": f"{browser_name}_{p_name}",
                                "source": sync_file,
                                "target": f"{browser_name.lower()}_{p_name}_sync_data.sqlite"
                            })

            for profile in self.source_root.glob("Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*"):
                profile_name = self._identity_from_path(profile)
                sync_targets.append({
                    "browser": f"Firefox_{profile_name}",
                    "source": profile / "signed_in_state.json",
                    "target": f"firefox_{profile_name}_sync_state.json"
                })
            for profile in self.source_root.glob("home/*/.mozilla/firefox/*"):
                profile_name = self._identity_from_path(profile)
                sync_targets.append({
                    "browser": f"Firefox_{profile_name}",
                    "source": profile / "signed_in_state.json",
                    "target": f"firefox_{profile_name}_sync_state.json"
                })
            for source in self.source_root.glob("Users/*/Library/Safari/CloudTabs.db"):
                source_name = self._identity_from_path(source.parent)
                sync_targets.append({
                    "browser": f"Safari_{source_name}",
                    "source": source,
                    "target": f"safari_{source_name}_cloud_tabs.sqlite"
                })
            for source in self.source_root.glob("Users/*/Library/Safari/SyncedRules.plist"):
                source_name = self._identity_from_path(source.parent)
                sync_targets.append({
                    "browser": f"Safari_{source_name}",
                    "source": source,
                    "target": f"safari_{source_name}_synced_rules.plist"
                })
        elif system == "Windows":
            local_appdata = Path(os.getenv('LOCALAPPDATA', user_home / 'AppData/Local'))
            roaming_appdata = Path(os.getenv('APPDATA', user_home / 'AppData/Roaming'))
            
            # Chrome/Edge Profile Discovery
            for browser_name, app_dir in [("Chrome", local_appdata / r"Google\Chrome\User Data"), 
                                          ("Edge", local_appdata / r"Microsoft\Edge\User Data")]:
                if app_dir.exists():
                    # Scan for Default and Profile X directories
                    profiles = [app_dir / "Default"] + list(app_dir.glob("Profile *"))
                    for profile in profiles:
                        sync_file = profile / "Sync Data"
                        if sync_file.exists():
                            p_name = profile.name.replace(" ", "_")
                            sync_targets.append({
                                "browser": f"{browser_name}_{p_name}",
                                "source": sync_file,
                                "target": f"{browser_name.lower()}_{p_name}_sync_data.sqlite"
                            })
            
            # Firefox Sync (Account Info)
            firefox_base = roaming_appdata / r"Mozilla\Firefox"
            if firefox_base.exists():
                for p in (firefox_base / "Profiles").glob("*"):
                    sync_targets.append({
                        "browser": f"Firefox_{p.name}",
                        "source": p / "signed_in_state.json",
                        "target": f"firefox_{p.name}_sync_state.json"
                    })
        elif system == "Darwin": # macOS
            # Chrome Sync
            sync_targets.append({
                "browser": "Chrome",
                "source": user_home / "Library/Application Support/Google/Chrome/Default/Sync Data",
                "target": "chrome_sync_data.sqlite"
            })
            # Safari iCloud Sync (iCloud Tabs/History)
            sync_targets.append({
                "browser": "Safari",
                "source": user_home / "Library/Safari/CloudTabs.db",
                "target": "safari_cloud_tabs.sqlite"
            })
            sync_targets.append({
                "browser": "Safari",
                "source": user_home / "Library/Safari/SyncedRules.plist",
                "target": "safari_synced_rules.plist"
            })

        for target in sync_targets:
            source = target["source"]
            dest = self.output_dir / target["target"]
            
            if source.exists():
                try:
                    print(f"    -> [!] Found {target['browser']} Sync Data at {source.name}")
                    if copy_resilient(source, dest):
                         file_hashes[target["target"]] = generate_sha256(dest)
                         success_count += 1
                except Exception as e:
                    print(f"    [-] Error copying sync data for {target['browser']}: {e}")
                    
        # Write manifest
        if file_hashes:
             write_hash_manifest(self.output_dir, file_hashes)
             
        print(f"[+] Cloud Sync Collection Complete: {success_count} artifacts secured.")
        return success_count > 0
