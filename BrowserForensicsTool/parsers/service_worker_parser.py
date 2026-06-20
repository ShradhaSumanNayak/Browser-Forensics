import sqlite3
import re
from pathlib import Path

class ServiceWorkerParser:
    """
    Parses Service Worker databases (SQLite), CacheStorage, and ScriptCache 
    to reconstruct "Ghost Sessions" (offline PWA interactions and background push data).
    """
    def __init__(self, artifact_path):
        self.artifact_path = Path(artifact_path)
        self.browser = self._browser_label()
        
    def _browser_label(self):
        name = self.artifact_path.name.lower()
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
        if "safari" in name:
            return "Safari"
        return "Unknown"

    def _extract_urls(self, text):
        if not text:
            return []
        try:
            matches = re.findall(r"https?://[^\s\"'<>{}\]]{5,500}", str(text), flags=re.IGNORECASE)
        except re.error:
            return []
        unique = []
        seen = set()
        for match in matches:
            cleaned = match.rstrip('",;)]}*')
            if cleaned not in seen:
                seen.add(cleaned)
                unique.append(cleaned)
        return unique

    def _parse_sqlite_db(self, db_path):
        results = []
        try:
            # Service Worker databases often contain info about registered workers
            conn = sqlite3.connect(f"file:{db_path.absolute()}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            # Check for standard SW tables (e.g., registrations, resources)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            if "registrations" in tables:
                try:
                    # scope, script_url, update_via_cache, etc.
                    rows = cursor.execute("SELECT scope, script_url FROM registrations").fetchall()
                    for row in rows:
                        scope, script_url = row
                        results.append({
                            "Browser": self.browser,
                            "Component": "Service Worker Registration",
                            "Scope": scope,
                            "Script URL": script_url,
                            "Evidence Source": str(db_path.name)
                        })
                except sqlite3.Error:
                    pass
                    
            conn.close()
        except sqlite3.Error:
            pass
            
        return results

    def _parse_cache_storage(self, cache_dir):
        # CacheStorage is usually an index + LevelDB or simple file blobs
        results = []
        files = list(cache_dir.rglob("*"))
        
        for f in files:
            if not f.is_file():
                continue
            # Basic textual extraction for URLs representing cached resources/push payloads
            try:
                raw = f.read_bytes()[:102400] # Read first 100KB to prevent huge memory spikes
                text = raw.decode("utf-8", errors="ignore")
                urls = self._extract_urls(text)
                if urls:
                    results.append({
                        "Browser": self.browser,
                        "Component": "CacheStorage Blob",
                        "Scope": "N/A",
                        "Script URL": "N/A",
                        "Evidence Source": f"{cache_dir.name}/{f.name}",
                        "Extracted URLs": " | ".join(urls[:5])
                    })
            except Exception:
                pass
                
        return results

    def parse(self):
        if not self.artifact_path.exists() or not self.artifact_path.is_dir():
            return []

        results = []
        
        # Look for Database directory
        db_dir = self.artifact_path / "Database"
        if db_dir.exists() and db_dir.is_dir():
            for db_file in db_dir.glob("*.sqlite*"):
                if db_file.is_file() and not db_file.name.endswith("-wal") and not db_file.name.endswith("-shm"):
                    results.extend(self._parse_sqlite_db(db_file))
        elif (self.artifact_path / "ServiceWorker").exists(): # Sometimes named directly
             sw_dir = self.artifact_path / "ServiceWorker" / "Database"
             if sw_dir.exists():
                 for db_file in sw_dir.glob("*.sqlite*"):
                     if db_file.is_file() and not db_file.name.endswith("-wal"):
                         results.extend(self._parse_sqlite_db(db_file))
                         
        # Look for CacheStorage
        cache_dir = self.artifact_path / "CacheStorage"
        if not cache_dir.exists():
             cache_dir = self.artifact_path / "ServiceWorker" / "CacheStorage"
             
        if cache_dir.exists() and cache_dir.is_dir():
             results.extend(self._parse_cache_storage(cache_dir))
             
        # ScriptCache
        script_dir = self.artifact_path / "ScriptCache"
        if not script_dir.exists():
             script_dir = self.artifact_path / "ServiceWorker" / "ScriptCache"
             
        if script_dir.exists() and script_dir.is_dir():
             results.extend(self._parse_cache_storage(script_dir))

        return results
