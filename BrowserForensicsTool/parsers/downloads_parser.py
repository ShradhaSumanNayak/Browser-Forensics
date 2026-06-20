import datetime
import plistlib
import sqlite3
from pathlib import Path

from parsers.browser_detection import browser_label, detect_browser, is_chromium, is_firefox_family


class DownloadsParser:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.browser = detect_browser(self.db_path.name)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        if is_chromium(self.browser):
            return "chromium"
        if is_firefox_family(self.browser):
            return "firefox"
        if self.browser == "safari" and self.db_path.name.lower().endswith(".plist"):
            return "safari"
        return "unknown"

    def _browser_label(self):
        return browser_label(browser=self.browser)

    def _chrome_time(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)
        except Exception:
            return ""

    def _firefox_time(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=timestamp)
        except Exception:
            return ""

    def _parse_safari_downloads(self):
        results = []
        browser_name = self._browser_label()

        try:
            with open(self.db_path, "rb") as f:
                plist_data = plistlib.load(f)
        except Exception as e:
            print(f"[-] Plist Error reading downloads {self.db_path}: {e}")
            return results

        def walk(node):
            if isinstance(node, dict):
                if any(key in node for key in ["DownloadEntryPath", "DownloadEntryURL"]):
                    source_url = node.get("DownloadEntryURL", "")
                    if isinstance(source_url, dict):
                        source_url = source_url.get("NS.relative", "") or source_url.get("URL", "")
                    if isinstance(source_url, list) and source_url:
                        source_url = source_url[0]

                    start_time = node.get("DownloadEntryDateAddedKey") or node.get("DownloadEntryDateStartedKey") or ""
                    end_time = node.get("DownloadEntryDateFinishedKey") or ""
                    results.append(
                        {
                            "Browser": browser_name,
                            "Target Path": node.get("DownloadEntryPath", ""),
                            "Source URL": source_url,
                            "Start Time": start_time,
                            "End Time": end_time,
                            "Total Bytes": node.get("DownloadEntryProgressTotalToLoad", ""),
                            "MIME Type": node.get("DownloadEntryMIMEType", ""),
                            "State": node.get("DownloadEntryState", "Unknown"),
                        }
                    )
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(plist_data)
        return results

    def parse(self):
        if not self.db_path.exists():
            return []

        if self.browser_type == "safari":
            results = self._parse_safari_downloads()
            print(f"[+] Parsed {len(results)} downloads from {self.db_path.name}.")
            return results

        results = []
        try:
            uri_path = f"file:{self.db_path.absolute()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            cursor = conn.cursor()

            if self.browser_type == "chromium":
                query = """
                SELECT current_path, target_path, start_time, end_time, total_bytes, mime_type, state, tab_url
                FROM downloads
                ORDER BY start_time DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    c_path, t_path, start, end, size, mime, state, url = row

                    state_str = "Complete"
                    if state == 0:
                        state_str = "InProgress"
                    elif state == 2:
                        state_str = "Cancelled"
                    elif state == 3:
                        state_str = "Interrupted"

                    results.append(
                        {
                            "Browser": self._browser_label(),
                            "Target Path": t_path or c_path,
                            "Source URL": url,
                            "Start Time": self._chrome_time(start),
                            "End Time": self._chrome_time(end),
                            "Total Bytes": size,
                            "MIME Type": mime,
                            "State": state_str,
                        }
                    )

            elif self.browser_type == "firefox":
                try:
                    query = """
                    SELECT p.url, a.content, p.title, a.lastModified, a.dateAdded
                    FROM moz_annos a
                    JOIN moz_places p ON a.place_id = p.id
                    JOIN moz_anno_attributes at ON a.anno_attribute_id = at.id
                    WHERE at.name = 'downloads/destinationFileURI'
                    ORDER BY a.lastModified DESC
                    """
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        url, file_uri, title, last_mod, date_added = row
                        file_path = file_uri.replace("file:///", "").replace("/", "\\")

                        results.append(
                            {
                                "Browser": self._browser_label(),
                                "Target Path": file_path,
                                "Source URL": url,
                                "Start Time": self._firefox_time(date_added),
                                "End Time": self._firefox_time(last_mod),
                                "Total Bytes": "Unknown",
                                "MIME Type": "Unknown",
                                "State": "Complete",
                            }
                        )
                except Exception as e:
                    print(f"    [-] Firefox downloads parsing Error: {e}")

            conn.close()
        except sqlite3.Error as e:
            print(f"[-] SQLite Error reading downloads {self.db_path}: {e}")

        print(f"[+] Parsed {len(results)} downloads from {self.db_path.name}.")
        return results
