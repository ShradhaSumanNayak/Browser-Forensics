import os
import shutil
import platform
import configparser
from pathlib import Path
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class FirefoxCollector:
    def __init__(self, output_dir, profile_paths=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.explicit_profiles = [Path(path) for path in profile_paths] if profile_paths else None
        self.firefox_path = self._get_firefox_basedir() if not self.explicit_profiles else None
        
        self.target_files = {
            "places.sqlite": "firefox_places.sqlite", # History, Bookmarks, Downloads
            "cookies.sqlite": "firefox_cookies.sqlite",
            "formhistory.sqlite": "firefox_autofill.sqlite",
            "logins.json": "firefox_logins.json",
            "key4.db": "firefox_key4.db", # Encryption key
            "key3.db": "firefox_key3.db", # Legacy encryption key
            "favicons.sqlite": "firefox_favicons.sqlite",
            "sessionstore.jsonlz4": "firefox_sessionstore.jsonlz4",
            "addons.json": "firefox_addons.json"
        }
        self.storage_dirs = {
            "storage": "firefox_browser_storage",
        }

    def _get_firefox_basedir(self):
        system = platform.system()
        user_home = Path.home()
        
        if system == "Windows":
            return Path(os.getenv('APPDATA', user_home / 'AppData/Roaming')) / r"Mozilla\Firefox"
        elif system == "Darwin": # macOS
            return user_home / "Library/Application Support/Firefox"
        elif system == "Linux":
            return user_home / ".mozilla/firefox"
        else:
            return None

    def _profile_label(self, profile_dir):
        if self.explicit_profiles is None:
            return profile_dir.name.lower()

        parts = list(profile_dir.parts)
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

        safe = "".join(char.lower() if char.isalnum() else "_" for char in f"{owner}_{profile_dir.name}")
        while "__" in safe:
            safe = safe.replace("__", "_")
        return safe.strip("_")

    def _get_profile_paths(self):
        """ Returns a list of all profile paths found in profiles.ini or the Profiles directory. """
        if self.explicit_profiles is not None:
            return [path for path in self.explicit_profiles if path.exists()]

        if not self.firefox_path or not self.firefox_path.exists():
            return []
            
        profile_paths = []
        profiles_ini = self.firefox_path / "profiles.ini"
        
        if profiles_ini.exists():
            config = configparser.ConfigParser()
            try:
                config.read(profiles_ini)
                for section in config.sections():
                    if section.startswith('Profile'):
                        is_relative = config[section].get('IsRelative', '1') == '1'
                        rel_path = config[section].get('Path')
                        if rel_path:
                            full_path = self.firefox_path / rel_path if is_relative else Path(rel_path)
                            if full_path.exists():
                                profile_paths.append(full_path)
            except Exception as e:
                print(f"[-] Error reading profiles.ini: {e}")
                    
        # Fallback: scan Profiles directory directly if profiles.ini didn't return anything or for safety
        profiles_dir = self.firefox_path / "Profiles"
        if profiles_dir.exists():
            for d in profiles_dir.iterdir():
                if d.is_dir() and (d / "places.sqlite").exists():
                    if d not in profile_paths:
                        profile_paths.append(d)
        
        # Unique list
        return list(set(profile_paths))

    def collect(self):
        print("[*] Starting Firefox Artifact Collection...")
        if self.explicit_profiles is None and (not self.firefox_path or not self.firefox_path.exists()):
            print("[-] Firefox installation data not found.")
            return False

        profile_dirs = self._get_profile_paths()
        if not profile_dirs:
            print("[-] Could not locate any Firefox profile directories.")
            return False
            
        print(f"[*] Found {len(profile_dirs)} Firefox Profiles.")

        total_success = 0
        file_hashes = {}
        
        for profile_dir in profile_dirs:
            p_name = self._profile_label(profile_dir)
            print(f"[*] Collecting from Profile: {profile_dir.name}")
            
            for source_name, target_base in self.target_files.items():
                # Prefix target filename with profile name to handle multiple profiles
                target_name = f"firefox_{p_name}_{target_base.replace('firefox_', '')}"
                
                source_file = profile_dir / source_name
                target_file = self.output_dir / target_name
                
                if source_file.exists():
                    try:
                        print(f"    -> Copying/Hashing {source_name} to {target_name}...")
                        if copy_resilient(source_file, target_file):
                            file_hashes[target_file.name] = generate_sha256(target_file)
                            total_success += 1
                        else:
                            print(f"    [-] Failed to copy locked file {source_name} even with resilient engine.")
                        
                        # Capture WAL and SHM for Deleted Data Recovery
                        if source_file.suffix == ".sqlite" or source_file.suffix == ".db":
                            for suffix in ["-wal", "-shm"]:
                                wal_shm_source = source_file.with_name(source_file.name + suffix)
                                if wal_shm_source.exists():
                                    wal_shm_target = target_file.with_name(target_file.name + suffix)
                                    print(f"        -> Capturing {suffix} for {source_name}...")
                                    copy_resilient(wal_shm_source, wal_shm_target)
                                    file_hashes[wal_shm_target.name] = generate_sha256(wal_shm_target)
                                    
                    except PermissionError:
                        print(f"    [-] Permission Error copying {source_name}.")
                    except Exception as e:
                        print(f"    [-] Error copying {source_name}: {e}")
                else:
                    # sessionstore.jsonlz4 is often in sessionstore-backups
                    if source_name == "sessionstore.jsonlz4":
                        backup_dir = profile_dir / "sessionstore-backups"
                        if backup_dir.exists():
                            recovery_file = backup_dir / "recovery.jsonlz4"
                            if recovery_file.exists():
                                 try:
                                    print(f"    -> Copying/Hashing session recovery to {target_name}...")
                                    if copy_resilient(recovery_file, target_file):
                                        file_hashes[target_file.name] = generate_sha256(target_file)
                                        total_success += 1
                                        continue
                                 except Exception as e:
                                    print(f"    [-] Error copying session recovery: {e}")
                    
                    if source_name == "places.sqlite":
                        # Critical for history/bookmarks/downloads
                        print(f"    [-] Warning: Critical artifact {source_name} missing in profile {p_name}")

            for source_name, target_base in self.storage_dirs.items():
                source_dir = profile_dir / source_name
                target_name = f"firefox_{p_name}_{target_base.replace('firefox_', '')}"
                target_dir = self.output_dir / target_name
                if not source_dir.exists() or not source_dir.is_dir():
                    continue
                try:
                    print(f"    -> Copying Browser Storage directory {source_name} to {target_name}...")
                    if target_dir.exists():
                        shutil.rmtree(target_dir)
                    shutil.copytree(str(source_dir), str(target_dir))
                    file_hashes.update(generate_directory_hashes(target_dir, base_name=target_dir.name))
                    total_success += 1
                except Exception as e:
                    print(f"    [-] Error copying browser storage directory {source_name}: {e}")

        # Write immutable manifest
        if file_hashes:
             write_hash_manifest(self.output_dir, file_hashes)
             print("    -> Generated Firefox SHA-256 entries in hash_manifest.txt")

        print(f"[+] Firefox Collection Complete: Copied {total_success} artifacts.")
        return total_success > 0
