import os
import shutil
import platform
from pathlib import Path
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class ChromeCollector:
    def __init__(self, output_dir, profile_path=None, artifact_prefix="chrome"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.chrome_path = Path(profile_path) if profile_path else self._get_chrome_path()
        self.artifact_prefix = artifact_prefix
        
        # Extended artifact list covering History, Cookies, Logins, Web Data, Bookmarks, and Sessions
        self.target_files = {
            "History": "chrome_history.sqlite",
            "Cookies": "chrome_cookies.sqlite",
            "Login Data": "chrome_login_data.sqlite", 
            "Web Data": "chrome_autofill.sqlite",
            "Bookmarks": "chrome_bookmarks.json",
            "Shortcuts": "chrome_shortcuts.sqlite",
            "Top Sites": "chrome_topsites.sqlite",
            "Favicons": "chrome_favicons.sqlite",
            "Current Session": "chrome_current_session",
            "Last Session": "chrome_last_session",
            "Current Tabs": "chrome_current_tabs",
            "Last Tabs": "chrome_last_tabs",
            "Preferences": "chrome_preferences.json",
            "Secure Preferences": "chrome_secure_preferences.json",
            "Cache": "chrome_cache_data"
        }
        self.storage_dirs = {
            "Local Storage/leveldb": "chrome_local_storage_leveldb",
            "IndexedDB": "chrome_indexeddb",
            "Service Worker": "chrome_service_worker",
        }
        
    def _get_chrome_path(self):
        system = platform.system()
        user_home = Path.home()
        
        if system == "Windows":
            return Path(os.getenv('LOCALAPPDATA', user_home / 'AppData/Local')) / r"Google\Chrome\User Data\Default"
        elif system == "Darwin": # macOS
            return user_home / "Library/Application Support/Google/Chrome/Default"
        elif system == "Linux":
            return user_home / ".config/google-chrome/Default"
        else:
            print(f"[-] Unsupported OS for Chrome collection: {system}")
            return None

    def _artifact_name(self, base_name):
        return base_name.replace("chrome_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        print("[*] Starting Chrome Artifact Collection...")
        if not self.chrome_path or not self.chrome_path.exists():
            print(f"[-] Chrome Profile not found at {self.chrome_path}")
            return False

        success_count = 0
        file_hashes = {}
        
        # Collect SQLite and JSON artifacts
        for source_name, target_name in self.target_files.items():
            source_file = self.chrome_path / source_name
            target_file = self.output_dir / self._artifact_name(target_name)
            
            # Subfolder checks (newer Chrome versions put Cookies/Logins in Network directory)
            if source_name == "Cookies" and not source_file.exists():
                source_file = self.chrome_path / "Network" / "Cookies"
            elif source_name == "Cache" and not source_file.exists():
                # Modern Chromium stores cache in Cache/Cache_Data
                source_file = self.chrome_path / "Cache" / "Cache_Data"
                if not source_file.exists():
                    source_file = self.chrome_path / "Cache"
                
            if source_file.exists():
                try:
                    if source_file.is_dir():
                        print(f"    -> Copying Cache directory to {target_name}...")
                        if target_file.exists():
                            shutil.rmtree(target_file)
                        # Use copytree for reliable full directory copy
                        shutil.copytree(str(source_file), str(target_file))
                        file_hashes.update(generate_directory_hashes(target_file, base_name=target_file.name))
                        success_count += 1
                        continue

                    print(f"    -> Copying/Hashing {source_name} to {target_name}...")
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
                    print(f"    [-] Permission Error copying {source_name}. Is Chrome running?")
                except Exception as e:
                    print(f"    [-] Error copying {source_name}: {e}")
            else:
                # Sessions/Tabs sometimes in a subfolder with timestamped names (modern Chromium)
                session_folder = self.chrome_path / "Sessions"
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
                            print(f"    -> Copying/Hashing Chrome {s_file.name} to {unique_target}...")
                            target = self.output_dir / unique_target
                            if copy_resilient(s_file, target):
                                file_hashes[unique_target] = generate_sha256(target)
                                success_count += 1
                        except Exception as e:
                            print(f"    [-] Error copying session file {s_file.name}: {e}")
                    continue
                print(f"    [-] Expected artifact {source_name} not found.")

        # Copy Local State (required for Password Decryption)
        local_state_path = self.chrome_path.parent / "Local State"
        if local_state_path.exists():
             try:
                 print("    -> Copying/Hashing Chrome Local State...")
                 target = self.output_dir / self._artifact_name("chrome_local_state.json")
                 if copy_resilient(local_state_path, target):
                     file_hashes[target.name] = generate_sha256(target)
                     success_count += 1
             except Exception as e:
                 print(f"    [-] Error copying Local State: {e}")

        for source_name, target_name in self.storage_dirs.items():
            source_dir = self.chrome_path / source_name
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
        
        print(f"[+] Chrome Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0

if __name__ == "__main__":
    collector = ChromeCollector("extracted_evidence")
    collector.collect()
