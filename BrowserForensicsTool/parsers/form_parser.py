import sqlite3
import datetime
from pathlib import Path

from parsers.browser_detection import browser_label, detect_browser, is_chromium, is_firefox_family


class FormParser:
    """
    Parses Autofill data, form history, and search engine keywords across Chromium and Firefox.
    """

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.browser = detect_browser(self.db_path.name)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        if is_chromium(self.browser):
            return "chrome_edge"
        if is_firefox_family(self.browser):
            return "firefox"
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

    def parse(self):
        if not self.db_path.exists():
            return []

        results = []
        try:
            uri_path = f"file:{self.db_path.absolute()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            cursor = conn.cursor()

            if self.browser_type == "chrome_edge":
                # 1. Autofill Data (Names, Emails, Addresses)
                try:
                    query = "SELECT name, value, date_created, count FROM autofill"
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        name, value, created, count = row
                        results.append({
                            "Browser": self._browser_label(),
                            "Type": "Autofill Entry",
                            "Field Name": name,
                            "Value": value,
                            "Date Created": self._chrome_time(created),
                            "Usage Count": count
                        })
                except sqlite3.Error:
                    pass

                # 2. Search Keywords (Address Bar Searches)
                try:
                    query = """
                    SELECT term, last_visit_time
                    FROM keyword_search_terms
                    ORDER BY last_visit_time DESC
                    """
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        term, last_visit = row
                        results.append({
                            "Browser": self._browser_label(),
                            "Type": "Search Term",
                            "Field Name": "Search Engine",
                            "Value": term,
                            "Date Created": self._chrome_time(last_visit),
                            "Usage Count": ""
                        })
                except sqlite3.Error:
                    pass

            elif self.browser_type == "firefox":
                try:
                    query = "SELECT fieldname, value, firstUsed, lastUsed, timesUsed FROM moz_formhistory"
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        fname, value, first, last, count = row
                        results.append({
                            "Browser": self._browser_label(),
                            "Type": "Form History",
                            "Field Name": fname,
                            "Value": value,
                            "Date Created": self._firefox_time(first),
                            "Usage Count": count
                        })
                except sqlite3.Error:
                    pass

            conn.close()
        except sqlite3.Error as e:
            print(f"[-] SQLite Error reading forms {self.db_path}: {e}")

        print(f"[+] Parsed {len(results)} form/autofill entries from {self.db_path.name}.")
        return results
