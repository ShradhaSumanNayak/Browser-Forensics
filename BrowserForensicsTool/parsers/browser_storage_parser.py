import json
import re
import sqlite3
from pathlib import Path


class BrowserStorageParser:
    def __init__(self, artifact_path, max_records=500):
        self.artifact_path = Path(artifact_path)
        self.max_records = max_records
        self.browser = self._browser_label()
        self.storage_category = self._storage_category()
        self._seen = set()

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

    def _storage_category(self):
        name = self.artifact_path.name.lower()
        if "indexeddb" in name:
            return "IndexedDB"
        if "service_worker" in name:
            return "Service Worker"
        if "local_storage" in name:
            return "Local Storage"
        if "storage" in name:
            return "Browser Storage"
        return "Browser Storage"

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
            cleaned = match.rstrip('",;)]}')
            if cleaned not in seen:
                seen.add(cleaned)
                unique.append(cleaned)
        return unique[:10]

    def _infer_origin_from_path(self, file_path):
        parts = [part for part in file_path.parts if part]
        for part in reversed(parts):
            lowered = part.lower()
            if any(token in lowered for token in ["http", "https", "ftp", ".indexeddb", "localstorage", "leveldb"]):
                normalized = part.replace("+++", "://").replace("^", ":").replace("_", "/")
                normalized = normalized.replace(".indexeddb.leveldb", "").replace(".sqlite", "")
                normalized = normalized.replace(".localstorage", "")
                return normalized
        return ""

    def _record(self, source_file, key="", value="", urls=None, origin="", evidence_type="Key/Value"):
        urls = urls or []
        if len(self._seen) >= self.max_records:
            return None

        record = {
            "Browser": self.browser,
            "Storage Category": self.storage_category,
            "Evidence Type": evidence_type,
            "Origin / Scope": origin or self._infer_origin_from_path(source_file.relative_to(self.artifact_path)),
            "Source File": str(source_file.relative_to(self.artifact_path)).replace("\\", "/"),
            "Key": str(key)[:200],
            "Value Preview": str(value)[:500],
            "URL Candidates": " | ".join(urls[:5]),
        }
        signature = tuple(record.items())
        if signature in self._seen:
            return None
        self._seen.add(signature)
        return record

    def _read_text_bytes(self, file_path, limit=512000):
        try:
            raw = file_path.read_bytes()[:limit]
        except Exception:
            return ""
        return raw.decode("utf-8", errors="ignore")

    def _parse_textual(self, file_path):
        results = []
        text = self._read_text_bytes(file_path)
        if not text:
            return results

        urls = self._extract_urls(text)
        if urls:
            record = self._record(file_path, key="embedded_urls", value=text[:200], urls=urls, evidence_type="Embedded URLs")
            if record:
                results.append(record)

        for line in text.splitlines():
            if len(results) >= 20 or len(self._seen) >= self.max_records:
                break
            if "=" in line and len(line) < 800:
                key, value = line.split("=", 1)
                line_urls = self._extract_urls(value) or self._extract_urls(key)
                record = self._record(file_path, key=key.strip(), value=value.strip(), urls=line_urls)
                if record:
                    results.append(record)
            elif ":" in line and len(line) < 800:
                key, value = line.split(":", 1)
                line_urls = self._extract_urls(value) or self._extract_urls(key)
                record = self._record(file_path, key=key.strip(), value=value.strip(), urls=line_urls)
                if record:
                    results.append(record)

        return results

    def _parse_json(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                data = json.load(handle)
        except Exception:
            return self._parse_textual(file_path)

        results = []

        def walk(node, prefix=""):
            if len(results) >= 50 or len(self._seen) >= self.max_records:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    child_prefix = f"{prefix}.{key}" if prefix else str(key)
                    walk(value, child_prefix)
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{prefix}[{index}]")
            else:
                urls = self._extract_urls(node) or self._extract_urls(prefix)
                record = self._record(file_path, key=prefix, value=node, urls=urls)
                if record:
                    results.append(record)

        walk(data)
        return results

    def _parse_sqlite(self, file_path):
        results = []
        try:
            conn = sqlite3.connect(f"file:{file_path.absolute()}?mode=ro", uri=True)
            cursor = conn.cursor()
            tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables[:20]:
                if len(self._seen) >= self.max_records:
                    break
                try:
                    columns = [row[1] for row in cursor.execute(f'PRAGMA table_info("{table}")')]
                except sqlite3.Error:
                    continue
                text_columns = columns[:6]
                if not text_columns:
                    continue
                select_list = ", ".join(f'"{column}"' for column in text_columns)
                try:
                    rows = cursor.execute(f'SELECT {select_list} FROM "{table}" LIMIT 25').fetchall()
                except sqlite3.Error:
                    continue
                for row in rows:
                    if len(self._seen) >= self.max_records:
                        break
                    pairs = list(zip(text_columns, row))
                    line = "; ".join(f"{key}={value}" for key, value in pairs if value not in ("", None))
                    urls = self._extract_urls(line)
                    for key, value in pairs:
                        if value in ("", None):
                            continue
                        record = self._record(
                            file_path,
                            key=f"{table}.{key}",
                            value=value,
                            urls=urls,
                            evidence_type="SQLite Storage Entry",
                        )
                        if record:
                            results.append(record)
                            if len(results) >= 100:
                                break
                    if len(results) >= 100:
                        break
            conn.close()
        except sqlite3.Error:
            return self._parse_textual(file_path)
        return results

    def _parse_file(self, file_path):
        suffix = file_path.suffix.lower()
        if suffix in {".json"}:
            return self._parse_json(file_path)
        if suffix in {".sqlite", ".db", ".localstorage"}:
            return self._parse_sqlite(file_path)
        if suffix in {".log", ".ldb", ".txt", ".log.old", ".sst"} or file_path.name.lower().endswith(".sqlite-wal"):
            return self._parse_textual(file_path)
        return self._parse_textual(file_path)

    def parse(self):
        if not self.artifact_path.exists() or not self.artifact_path.is_dir():
            return []

        results = []
        files = sorted(path for path in self.artifact_path.rglob("*") if path.is_file())
        for file_path in files:
            if len(self._seen) >= self.max_records:
                break
            results.extend(self._parse_file(file_path))
        return results
