import shutil
import platform
from pathlib import Path
from utils.hasher import generate_sha256, generate_directory_hashes, write_hash_manifest
from utils.io_helper import copy_resilient

class SafariCollector:
    def __init__(self, output_dir, profile_path=None, artifact_prefix="safari"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.safari_path = Path(profile_path) if profile_path else self._get_safari_path()
        self.artifact_prefix = artifact_prefix
        
        # Safari specific artifacts
        self.target_files = {
            "History.db": "safari_history.db",
            "Bookmarks.plist": "safari_bookmarks.plist",
            "Downloads.plist": "safari_downloads.plist"
        }
        self.storage_dirs = {}
        
        # Cookies are usually stored separately
        if profile_path:
            profile_root = Path(profile_path).parent
            self.cookies_path = profile_root / "Cookies" / "Cookies.binarycookies"
            self.storage_dirs = {
                str(profile_root / "Safari" / "LocalStorage"): "safari_local_storage",
                str(profile_root / "Containers" / "com.apple.Safari" / "Data" / "Library" / "WebKit" / "WebsiteData"): "safari_website_data",
            }
        else:
            self.cookies_path = Path.home() / "Library/Cookies/Cookies.binarycookies"
            home = Path.home()
            self.storage_dirs = {
                str(home / "Library" / "Safari" / "LocalStorage"): "safari_local_storage",
                str(home / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "WebKit" / "WebsiteData"): "safari_website_data",
            }
        
    def _get_safari_path(self):
        system = platform.system()
        user_home = Path.home()
        
        if system == "Darwin": # macOS
            return user_home / "Library/Safari"
        else:
            return None

    def _artifact_name(self, base_name):
        return base_name.replace("safari_", f"{self.artifact_prefix}_", 1)

    def collect(self):
        print("[*] Starting Safari Artifact Collection...")
        if not self.safari_path:
            print("[-] Safari collection is only supported on macOS.")
            return False
            
        if not self.safari_path.exists():
            print(f"[-] Safari Profile not found at {self.safari_path}")
            return False

        success_count = 0
        file_hashes = {}
        
        for source_name, target_name in self.target_files.items():
            source_file = self.safari_path / source_name
            target_file = self.output_dir / self._artifact_name(target_name)
                
            if source_file.exists():
                try:
                    print(f"    -> Copying/Hashing Safari {source_name} to {target_name}...")
                    if copy_resilient(source_file, target_file):
                        file_hashes[target_file.name] = generate_sha256(target_file)
                        success_count += 1
                    else:
                        print(f"    [-] Failed to copy locked file {source_name}.")
                except PermissionError:
                    print(f"    [-] Permission Error copying {source_name}. Is Safari running?")
                except Exception as e:
                    print(f"    [-] Error copying {source_name}: {e}")
            else:
                print(f"    [-] Expected Safari artifact {source_name} not found.")

        # Special handler for binary cookies
        if self.cookies_path.exists():
             try:
                 print("    -> Copying/Hashing Safari Cookies...")
                 target_file = self.output_dir / self._artifact_name("safari_cookies.binarycookies")
                 if copy_resilient(self.cookies_path, target_file):
                     file_hashes[target_file.name] = generate_sha256(target_file)
                     success_count += 1
             except Exception:
                 pass

        for source_name, target_name in self.storage_dirs.items():
             source_dir = Path(source_name)
             target_dir = self.output_dir / self._artifact_name(target_name)
             if not source_dir.exists() or not source_dir.is_dir():
                 continue
             try:
                 print(f"    -> Copying Browser Storage directory {source_dir.name} to {target_name}...")
                 if target_dir.exists():
                     shutil.rmtree(target_dir)
                 shutil.copytree(str(source_dir), str(target_dir))
                 file_hashes.update(generate_directory_hashes(target_dir, base_name=target_dir.name))
                 success_count += 1
             except Exception as e:
                 print(f"    [-] Error copying browser storage directory {source_dir}: {e}")
                 
        # Write immutable manifest
        if file_hashes:
             write_hash_manifest(self.output_dir, file_hashes)
             print("    -> Generated Safari SHA-256 entries in hash_manifest.txt")
                 
        print(f"[+] Safari Collection Complete: Copied {success_count} artifacts.")
        return success_count > 0
