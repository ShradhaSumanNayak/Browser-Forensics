import os
import shutil
import platform
from pathlib import Path

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class BraveCollector:
    """
    Locates and extracts forensic artifacts from Brave Browser.
    """
    def __init__(self, output_dir, profile_path=None, artifact_prefix="brave"):
        self.output_dir = Path(output_dir)
        self.brave_path = Path(profile_path) if profile_path else self._get_brave_path()
        self.artifact_prefix = artifact_prefix
        
        self.target_files = {
            "History": "brave_history.sqlite",
            "Cookies": "brave_cookies.sqlite",
            "Login Data": "brave_login_data.sqlite",
            "Web Data": "brave_autofill.sqlite",
            "Bookmarks": "brave_bookmarks.json",
            "Shortcuts": "brave_shortcuts.sqlite",
            "Top Sites": "brave_topsites.sqlite",
            "Favicons": "brave_favicons.sqlite",
            "Current Session": "brave_current_session",
            "Last Session": "brave_last_session",
            "Current Tabs": "brave_current_tabs",
            "Last Tabs": "brave_last_tabs",
            "Preferences": "brave_preferences.json",
            "Secure Preferences": "brave_secure_preferences.json",
            "Cache": "brave_cache_data"
        }
        self.storage_dirs = {
            "Local Storage/leveldb": "brave_local_storage_leveldb",
            "IndexedDB": "brave_indexeddb",
            "Service Worker": "brave_service_worker",
        }

    def _get_brave_path(self):
        """ Dynamically paths to the Brave directory across operating systems. """
        system = platform.system()
        if system == "Windows":
             return Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default"
        elif system == "Darwin":
             return Path.home() / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Default"
        elif system == "Linux":
             return Path.home() / ".config" / "BraveSoftware" / "Brave-Browser" / "Default"
        return None

    def _artifact_name(self, base_name):
        return base_name.replace("brave_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        """ Copies Brave files securely, applying SHA-256 block hashing on creation. """
        print("\n[*] Starting Brave Artifact Collection...")
        if not self.brave_path or not self.brave_path.exists():
             print(f"[-] Brave profile not found at {self.brave_path}")
             return False

        self.output_dir.mkdir(parents=True, exist_ok=True)
        success_count = 0
        file_hashes = {}

        for source_name, target_name in self.target_files.items():
            source_file = self.brave_path / source_name
            if source_name == "Cache" and not source_file.exists():
                source_file = self.brave_path / "Cache" / "Cache_Data"
                if not source_file.exists():
                    source_file = self.brave_path / "Cache"
            target = self.output_dir / self._artifact_name(target_name)
            if source_file.exists():
                try:
                    if source_file.is_dir():
                        print(f"    -> Copying Cache directory to {target_name}...")
                        if target.exists():
                            shutil.rmtree(target)
                        shutil.copytree(str(source_file), str(target))
                        file_hashes.update(generate_directory_hashes(target, base_name=target.name))
                        success_count += 1
                        continue

                    print(f"    -> Copying/Hashing Brave {source_name} to {target_name}...")
                    if copy_resilient(source_file, target):
                        file_hashes[target.name] = generate_sha256(target)
                        success_count += 1
                    else:
                        print(f"    [-] Failed to copy locked file {source_name} even with resilient engine.")

                    # Capture WAL and SHM for Deleted Data Recovery
                    for suffix in ["-wal", "-shm"]:
                        wal_shm_source = source_file.with_name(source_file.name + suffix)
                        if wal_shm_source.exists():
                            wal_shm_target = target.with_name(target.name + suffix)
                            print(f"        -> Capturing {suffix} for {source_name}...")
                            copy_resilient(wal_shm_source, wal_shm_target)
                            file_hashes[wal_shm_target.name] = generate_sha256(wal_shm_target)
                            
                except Exception as e:
                    print(f"    [-] Error copying {source_name}: {e}")
            else:
                # Sessions/Tabs sometimes in a subfolder with timestamped names (modern Chromium)
                session_folder = self.brave_path / "Sessions"
                if session_folder.exists():
                    # Map 'Current Session' or 'Last Session' to 'Session*'
                    # Map 'Current Tabs' or 'Last Tabs' to 'Tabs*'
                    pattern = "Session" if "Session" in source_name else "Tabs"
                    
                    potential_files = list(session_folder.glob(f"{pattern}*"))
                    for s_file in potential_files:
                        try:
                            # Avoid copying lock files or unrelated items
                            if s_file.is_dir() or s_file.suffix in ['.tmp', '.lock']:
                                continue

                            # Create a unique target name if multiple files exist
                            unique_target = f"{self.artifact_prefix}_{s_file.name.lower()}.bin"
                            print(f"    -> Copying/Hashing Brave {s_file.name} to {unique_target}...")
                            target = self.output_dir / unique_target
                            if copy_resilient(s_file, target):
                                file_hashes[unique_target] = generate_sha256(target)
                                success_count += 1
                        except Exception as e:
                            print(f"    [-] Error copying session file {s_file.name}: {e}")
                    continue
                print(f"    [-] Expected artifact {source_name} not found.")

        # Copy Local State (required for Password Decryption)
        local_state_path = self.brave_path.parent / "Local State"
        if local_state_path.exists():
             try:
                 print("    -> Copying/Hashing Brave Local State...")
                 target = self.output_dir / self._artifact_name("brave_local_state.json")
                 if copy_resilient(local_state_path, target):
                     file_hashes[target.name] = generate_sha256(target)
                     success_count += 1
             except Exception as e:
                 print(f"    [-] Error copying Local State: {e}")

        for source_name, target_name in self.storage_dirs.items():
            source_dir = self.brave_path / source_name
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
        
        print(f"[+] Brave Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0
