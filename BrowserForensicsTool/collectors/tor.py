import os
import shutil
import platform
from pathlib import Path

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class TorCollector:
    """
    Locates and extracts forensic artifacts from Tor Browser.
    Tor is based on Firefox, so the artifacts are SQLite/JSON (places.sqlite, etc.)
    Note: Tor heavily restricts writing artifacts to disk, but we still search
    in case the user modified privacy settings or downloaded files.
    """
    def __init__(self, output_dir, profile_path=None, artifact_prefix="tor"):
        self.output_dir = Path(output_dir)
        self.tor_path = Path(profile_path) if profile_path else self._get_tor_path()
        self.artifact_prefix = artifact_prefix
        
        self.target_files = {
            "places.sqlite": "tor_places.sqlite",
            "cookies.sqlite": "tor_cookies.sqlite",
            "formhistory.sqlite": "tor_formhistory.sqlite",
            "logins.json": "tor_logins.json",
            "key4.db": "tor_key4.db",
            "favicons.sqlite": "tor_favicons.sqlite",
            "sessionstore.jsonlz4": "tor_sessionstore.jsonlz4"
        }
        self.storage_dirs = {
            "storage": "tor_browser_storage",
        }

    def _get_tor_path(self):
        """ Dynamically attempts to find the portable Tor installation. """
        system = platform.system()
        user_home = Path.home()
        
        # Standard Desktop installation path on Windows
        desktops = [user_home / "Desktop", user_home / "OneDrive" / "Desktop"]
        for desktop in desktops:
            tor_base = desktop / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser"
            if tor_base.exists():
                 # Look for the default profile
                 for d in tor_base.iterdir():
                     if d.is_dir() and "default" in d.name:
                         return d
        
        # macOS/Linux standard portable spots
        if system == "Darwin":
            tor_base = user_home / "Library/Application Support/TorBrowser-Data/Browser"
            if tor_base.exists():
                for d in tor_base.iterdir():
                    if d.is_dir() and "default" in d.name:
                        return d
        elif system == "Linux":
            tor_base = user_home / ".tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser"
            if tor_base.exists():
                for d in tor_base.iterdir():
                    if d.is_dir() and "default" in d.name:
                        return d
                    
        return None

    def _artifact_name(self, base_name):
        return base_name.replace("tor_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        """ Copies Tor files securely, applying SHA-256 block hashing on creation. """
        print("\n[*] Starting Tor Artifact Collection...")
        if not self.tor_path or not self.tor_path.exists():
             print("[-] Tor profile not found at typical portable paths.")
             return False

        self.output_dir.mkdir(parents=True, exist_ok=True)
        success_count = 0
        file_hashes = {}

        for source_name, target_name in self.target_files.items():
            source_file = self.tor_path / source_name
            target_file = self.output_dir / self._artifact_name(target_name)
            
            if source_file.exists():
                try:
                    print(f"    -> Copying/Hashing Tor {source_name} to {target_name}...")
                    
                    if copy_resilient(source_file, target_file):
                        file_hashes[target_file.name] = generate_sha256(target_file)
                        success_count += 1
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
                                    
                except Exception as e:
                    print(f"    [-] Error copying {source_name}: {e}")
            else:
                # sessionstore.jsonlz4 is often in sessionstore-backups
                if source_name == "sessionstore.jsonlz4":
                    backup_dir = self.tor_path / "sessionstore-backups"
                    if backup_dir.exists():
                        recovery_file = backup_dir / "recovery.jsonlz4"
                        if recovery_file.exists():
                             try:
                                print(f"    -> Copying/Hashing Tor session recovery file to {target_name}...")
                                if copy_resilient(recovery_file, target_file):
                                    file_hashes[target_file.name] = generate_sha256(target_file)
                                    success_count += 1
                                    continue
                             except Exception as e:
                                print(f"    [-] Error copying Tor session recovery: {e}")
                
                pass # Tor aggressively deletes these, so silent pass

        for source_name, target_name in self.storage_dirs.items():
            source_dir = self.tor_path / source_name
            target_dir = self.output_dir / self._artifact_name(target_name)
            if not source_dir.exists() or not source_dir.is_dir():
                continue
            try:
                print(f"    -> Copying Browser Storage directory {source_name} to {target_name}...")
                if target_dir.exists():
                    shutil.rmtree(target_dir)
                shutil.copytree(str(source_dir), str(target_dir))
                file_hashes.update(generate_directory_hashes(target_dir, base_name=target_dir.name))
                success_count += 1
            except Exception as e:
                print(f"    [-] Error copying browser storage directory {source_name}: {e}")

        # Write immutable manifest
        if file_hashes:
             write_hash_manifest(self.output_dir, file_hashes)
             print("    -> Generated SHA-256 entries in hash_manifest.txt")
        
        print(f"[+] Tor Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0
