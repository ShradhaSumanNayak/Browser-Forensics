import json
import sqlite3
import datetime
import plistlib
from pathlib import Path

class BookmarksParser:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.file_path.name.lower()
        if any(token in name for token in ["chrome", "edge", "brave", "opera"]):
            return "chromium"
        elif "firefox" in name or "tor" in name:
            return "firefox"
        elif "safari" in name or name.endswith(".plist"):
            return "safari"
        return "unknown"

    def _browser_label(self):
        name = self.file_path.name.lower()
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

    def _chrome_time(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(timestamp))
        except Exception:
            return ""

    def _parse_chrome_folder(self, node, folder_name, results):
        if "children" in node:
            for child in node["children"]:
                if child.get("type") == "url":
                    results.append({
                        "Browser": self._browser_label(),
                        "Folder": folder_name,
                        "Name": child.get("name", ""),
                        "URL": child.get("url", ""),
                        "Date Added": self._chrome_time(child.get("date_added", 0))
                    })
                elif child.get("type") == "folder":
                    self._parse_chrome_folder(child, folder_name + "/" + child.get("name", ""), results)

    def parse(self):
        if not self.file_path.exists():
            return []

        results = []
        if self.browser_type == "chromium":
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                roots = data.get("roots", {})
                for root_name, root_node in roots.items():
                    if isinstance(root_node, dict):
                        self._parse_chrome_folder(root_node, root_name, results)
                        
                print(f"[+] Parsed {len(results)} JSON bookmarks from {self.file_path.name}.")
            except Exception as e:
                 print(f"[-] Error parsing bookmarks JSON {self.file_path}: {e}")
                 
        elif self.browser_type == "firefox":
            # Firefox places.sqlite bookmarks logic
             try:
                uri_path = f"file:{self.file_path.absolute()}?mode=ro"
                conn = sqlite3.connect(uri_path, uri=True)
                cursor = conn.cursor()
                query = """
                SELECT b.title, p.url, b.dateAdded
                FROM moz_bookmarks b
                JOIN moz_places p ON b.fk = p.id
                WHERE b.type = 1
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    title, url, date_added = row
                    results.append({
                        "Browser": self._browser_label(),
                        "Folder": "Unknown",
                        "Name": title,
                        "URL": url,
                        "Date Added": datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=date_added) if date_added else ""
                    })
                conn.close()
                print(f"[+] Parsed {len(results)} SQLite bookmarks from {self.file_path.name}.")
             except sqlite3.Error as e:
                print(f"[-] SQLite Error reading bookmarks {self.file_path}: {e}")

        elif self.browser_type == "safari":
             try:
                 with open(self.file_path, 'rb') as f:
                     plist_data = plistlib.load(f)
                     
                 def parse_safari_node(node, folder="Root"):
                     if isinstance(node, dict):
                         if node.get('WebBookmarkType') == 'WebBookmarkTypeLeaf':
                             results.append({
                                 "Browser": self._browser_label(),
                                 "Folder": folder,
                                 "Name": node.get('URIDictionary', {}).get('title', 'Unknown'),
                                 "URL": node.get('URLString', ''),
                                 "Date Added": ""
                             })
                         elif node.get('WebBookmarkType') == 'WebBookmarkTypeList':
                             new_folder = f"{folder}/{node.get('Title', 'Unnamed')}"
                             for child in node.get('Children', []):
                                 parse_safari_node(child, new_folder)
                                 
                 parse_safari_node(plist_data)
                 print(f"[+] Parsed {len(results)} Plist bookmarks from {self.file_path.name}.")
             except Exception as e:
                 print(f"[-] Error parsing Safari Plist {self.file_path}: {e}")

        return results
