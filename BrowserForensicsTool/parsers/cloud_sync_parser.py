import json
import plistlib
import sqlite3
from pathlib import Path


class CloudSyncParser:
    """
    Best-effort parser for browser sync-state artifacts.
    Produces evidence summaries even when schemas vary by browser version.
    """

    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def _browser_label(self):
        name = self.file_path.name.lower()
        if "chrome" in name:
            return "Chrome"
        if "edge" in name:
            return "Edge"
        if "firefox" in name:
            return "Firefox"
        if "safari" in name:
            return "Safari"
        return "Unknown"

    def _flatten(self, node, prefix=""):
        items = []
        if isinstance(node, dict):
            for key, value in node.items():
                new_prefix = f"{prefix}.{key}" if prefix else str(key)
                items.extend(self._flatten(value, new_prefix))
        elif isinstance(node, list):
            for idx, value in enumerate(node):
                items.extend(self._flatten(value, f"{prefix}[{idx}]"))
        else:
            items.append((prefix, node))
        return items

    def _parse_json(self):
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        results = []
        for key, value in self._flatten(data)[:200]:
            results.append(
                {
                    "Browser": self._browser_label(),
                    "Artifact Type": "Cloud Sync State",
                    "Source File": self.file_path.name,
                    "Key": key,
                    "Value": value,
                    "Record Count": "",
                }
            )
        return results

    def _parse_plist(self):
        with open(self.file_path, "rb") as f:
            data = plistlib.load(f)

        results = []
        for key, value in self._flatten(data)[:200]:
            results.append(
                {
                    "Browser": self._browser_label(),
                    "Artifact Type": "Cloud Sync Metadata",
                    "Source File": self.file_path.name,
                    "Key": key,
                    "Value": value,
                    "Record Count": "",
                }
            )
        return results

    def _parse_sqlite(self):
        results = []
        uri_path = self.file_path.absolute().as_posix()
        conn = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            try:
                count = cursor.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            except sqlite3.Error:
                count = ""

            results.append(
                {
                    "Browser": self._browser_label(),
                    "Artifact Type": "Cloud Sync Table Summary",
                    "Source File": self.file_path.name,
                    "Key": table,
                    "Value": "",
                    "Record Count": count,
                }
            )

            try:
                columns = [row[1] for row in cursor.execute(f'PRAGMA table_info("{table}")')]
            except sqlite3.Error:
                columns = []

            interesting = [
                col
                for col in columns
                if any(token in col.lower() for token in ["url", "title", "device", "tab", "name"])
            ]
            if not interesting:
                continue

            select_cols = interesting[:3]
            select_list = ", ".join(f'"{col}"' for col in select_cols)
            try:
                preview_query = f'SELECT {select_list} FROM "{table}" LIMIT 10'
                for row in cursor.execute(preview_query):
                    summary = " | ".join(f"{col}={value}" for col, value in zip(select_cols, row))
                    results.append(
                        {
                            "Browser": self._browser_label(),
                            "Artifact Type": "Cloud Sync Preview",
                            "Source File": self.file_path.name,
                            "Key": table,
                            "Value": summary,
                            "Record Count": "",
                        }
                    )
            except sqlite3.Error:
                pass

        conn.close()
        return results

    def parse(self):
        if not self.file_path.exists():
            return []

        try:
            suffix = self.file_path.suffix.lower()
            if suffix == ".json":
                return self._parse_json()
            if suffix == ".plist":
                return self._parse_plist()
            return self._parse_sqlite()
        except Exception as e:
            print(f"[-] Error parsing cloud sync artifact {self.file_path}: {e}")
            return []
