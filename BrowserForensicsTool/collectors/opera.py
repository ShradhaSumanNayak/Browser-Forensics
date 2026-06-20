import os
import shutil
import platform
from pathlib import Path

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class OperaCollector:
    """
    Locates and extracts forensic artifacts from Opera Browser.
    """
    def __init__(self, output_dir, profile_path=None, artifact_prefix="opera"):
        self.output_dir = Path(output_dir)
        self.opera_path = Path(profile_path) if profile_path else self._get_opera_path()
        self.artifact_prefix = artifact_prefix
        
        self.target_files = {
            "History": "opera_history.sqlite",
            "Cookies": "opera_cookies.sqlite",
            "Login Data": "opera_login_data.sqlite",
            "Web Data": "opera_autofill.sqlite",
            "Bookmarks": "opera_bookmarks.json",
            "Shortcuts": "opera_shortcuts.sqlite",
            "Top Sites": "opera_topsites.sqlite",
            "Favicons": "opera_favicons.sqlite",
            "Current Session": "opera_current_session",
            "Last Session": "opera_last_session",
            "Current Tabs": "opera_current_tabs",
            "Last Tabs": "opera_last_tabs",
            "Preferences": "opera_preferences.json",
            "Secure Preferences": "opera_secure_preferences.json",
            "Cache": "opera_cache_data"
        }
        self.storage_dirs = {
            "Local Storage/leveldb": "opera_local_storage_leveldb",
            "IndexedDB": "opera_indexeddb",
            "Service Worker": "opera_service_worker",
        }

    def _get_opera_path(self):
        """ Dynamically paths to the Opera directory across operating systems. """
        system = platform.system()
        if system == "Windows":
             return Path(os.environ.get("APPDATA", "")) / "Opera Software" / "Opera Stable"
        elif system == "Darwin":
             return Path.home() / "Library" / "Application Support" / "com.operasoftware.Opera"
        elif system == "Linux":
             return Path.home() / ".config" / "opera"
        return None

    def _artifact_name(self, base_name):
        return base_name.replace("opera_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        """ Copies Opera files securely, applying SHA-256 block hashing on creation. """
        print("\n[*] Starting Opera Artifact Collection...")
        if not self.opera_path or not self.opera_path.exists():
             print(f"[-] Opera profile not found at {self.opera_path}")
             return False

        self.output_dir.mkdir(parents=True, exist_ok=True)
        success_count = 0
        file_hashes = {}

        for source_name, target_name in self.target_files.items():
            source_file = self.opera_path / source_name
            if source_file.exists():
                try:
                    if source_file.is_dir():
                         target_file = self.output_dir / self._artifact_name(target_name)
                         print(f"    -> Copying Cache directory to {target_name}...")
                         if target_file.exists():
                             shutil.rmtree(target_file)
                         target_file.mkdir(parents=True, exist_ok=True)
                         count = 0
                         for f in source_file.glob("f_*"):
                             if count > 100:
                                 break
                             shutil.copy2(f, target_file / f.name)
                             count += 1
                         file_hashes.update(generate_directory_hashes(target_file, base_name=target_file.name))
                         success_count += 1
                         continue

                    print(f"    -> Copying/Hashing Opera {source_name} to {target_name}...")
                    target = self.output_dir / self._artifact_name(target_name)
                    
                    # Try direct copy first
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
                session_folder = self.opera_path / "Sessions"
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
                            print(f"    -> Copying/Hashing Opera {s_file.name} to {unique_target}...")
                            target = self.output_dir / unique_target
                            if copy_resilient(s_file, target):
                                file_hashes[unique_target] = generate_sha256(target)
                                success_count += 1
                        except Exception as e:
                            print(f"    [-] Error copying session file {s_file.name}: {e}")
                    continue
                print(f"    [-] Expected artifact {source_name} not found.")       

        # Copy Local State (required for Password Decryption)
        # For Opera, Local State is in the same directory or parent directory
        # In modern Opera (Chromium-based), Local State is in the parent of the profile, or in the profile itself depending on "Opera Stable" vs "Opera GX"
        local_state_path = self.opera_path / "Local State"
        if not local_state_path.exists():
             local_state_path = self.opera_path.parent / "Local State"
             
        if local_state_path.exists():
             try:
                 print("    -> Copying/Hashing Opera Local State...")
                 target = self.output_dir / self._artifact_name("opera_local_state.json")
                 if copy_resilient(local_state_path, target):
                     file_hashes[target.name] = generate_sha256(target)
                     success_count += 1
             except Exception as e:
                 print(f"    [-] Error copying Local State: {e}")

        for source_name, target_name in self.storage_dirs.items():
            source_dir = self.opera_path / source_name
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
        
        print(f"[+] Opera Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0
