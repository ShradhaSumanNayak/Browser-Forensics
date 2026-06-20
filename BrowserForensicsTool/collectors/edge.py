import os
import shutil
import platform
from pathlib import Path
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class EdgeCollector:
    def __init__(self, output_dir, profile_path=None, artifact_prefix="edge"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.edge_path = Path(profile_path) if profile_path else self._get_edge_path()
        self.artifact_prefix = artifact_prefix
        
        # Edge uses Chromium backend, so artifacts are practically identical to Chrome
        self.target_files = {
            "History": "edge_history.sqlite",
            "Cookies": "edge_cookies.sqlite",
            "Login Data": "edge_login_data.sqlite", 
            "Web Data": "edge_autofill.sqlite",
            "Bookmarks": "edge_bookmarks.json",
            "Shortcuts": "edge_shortcuts.sqlite",
            "Top Sites": "edge_topsites.sqlite",
            "Favicons": "edge_favicons.sqlite",
            "Current Session": "edge_current_session",
            "Last Session": "edge_last_session",
            "Current Tabs": "edge_current_tabs",
            "Last Tabs": "edge_last_tabs",
            "Preferences": "edge_preferences.json",
            "Secure Preferences": "edge_secure_preferences.json",
            "Cache": "edge_cache_data"
        }
        self.storage_dirs = {
            "Local Storage/leveldb": "edge_local_storage_leveldb",
            "IndexedDB": "edge_indexeddb",
            "Service Worker": "edge_service_worker",
        }
        
    def _get_edge_path(self):
        system = platform.system()
        user_home = Path.home()
        
        if system == "Windows":
            return Path(os.getenv('LOCALAPPDATA', user_home / 'AppData/Local')) / r"Microsoft\Edge\User Data\Default"
        elif system == "Darwin": # macOS
            return user_home / "Library/Application Support/Microsoft Edge/Default"
        elif system == "Linux":
            return user_home / ".config/microsoft-edge/Default"
        else:
            return None

    def _artifact_name(self, base_name):
        return base_name.replace("edge_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        print("[*] Starting Microsoft Edge Artifact Collection...")
        if not self.edge_path or not self.edge_path.exists():
            print(f"[-] Edge Profile not found at {self.edge_path}")
            return False

        success_count = 0
        file_hashes = {}
        
        for source_name, target_name in self.target_files.items():
            source_file = self.edge_path / source_name
            target_file = self.output_dir / self._artifact_name(target_name)
            
            # Edge Network folder for newer builds
            if source_name == "Cookies" and not source_file.exists():
                source_file = self.edge_path / "Network" / "Cookies"
            elif source_name == "Cache" and not source_file.exists():
                # Modern Chromium stores cache in Cache/Cache_Data
                source_file = self.edge_path / "Cache" / "Cache_Data"
                if not source_file.exists():
                    source_file = self.edge_path / "Cache"
                
            if source_file.exists():
                try:
                    if source_file.is_dir():
                        print(f"    -> Copying Cache directory to {target_name}...")
                        if target_file.exists():
                            shutil.rmtree(target_file)
                        shutil.copytree(str(source_file), str(target_file))
                        file_hashes.update(generate_directory_hashes(target_file, base_name=target_file.name))
                        success_count += 1
                        continue

                    print(f"    -> Copying/Hashing Edge {source_name} to {target_name}...")
                    if copy_resilient(source_file, target_file):
                        file_hashes[target_file.name] = generate_sha256(target_file)
                        success_count += 1
                    else:
                        print(f"    [-] Failed to copy locked file {source_name} even with resilient engine.")
                    
                    # Capture WAL and SHM for Deleted Data Recovery
                    for suffix in ["-wal", "-shm"]:
                        wal_shm_source = source_file.with_name(source_file.name + suffix)
                        if wal_shm_source.exists():
                            wal_shm_target = target_file.with_name(target_file.name + suffix)
                            print(f"        -> Capturing {suffix} for {source_name}...")
                            copy_resilient(wal_shm_source, wal_shm_target)
                            file_hashes[wal_shm_target.name] = generate_sha256(wal_shm_target)
                            
                except PermissionError:
                    print(f"    [-] Permission Error copying {source_name}. Is Edge running?")
                except Exception as e:
                    print(f"    [-] Error copying {source_name}: {e}")
            else:
                # Sessions/Tabs sometimes in a subfolder with timestamped names (modern Chromium)
                session_folder = self.edge_path / "Sessions"
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
                            print(f"    -> Copying/Hashing Edge {s_file.name} to {unique_target}...")
                            target = self.output_dir / unique_target
                            if copy_resilient(s_file, target):
                                file_hashes[unique_target] = generate_sha256(target)
                                success_count += 1
                        except Exception as e:
                            print(f"    [-] Error copying session file {s_file.name}: {e}")
                    continue
                print(f"    [-] Expected artifact {source_name} not found.")

        # Copy Local State (required for Password Decryption)
        local_state_path = self.edge_path.parent / "Local State"
        if local_state_path.exists():
             try:
                 print("    -> Copying/Hashing Edge Local State...")
                 target = self.output_dir / self._artifact_name("edge_local_state.json")
                 if copy_resilient(local_state_path, target):
                     file_hashes[target.name] = generate_sha256(target)
                     success_count += 1
             except Exception as e:
                 print(f"    [-] Error copying Local State: {e}")

        for source_name, target_name in self.storage_dirs.items():
            source_dir = self.edge_path / source_name
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
             print("    -> Generated Edge SHA-256 entries in hash_manifest.txt")

        print(f"[+] Edge Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0
