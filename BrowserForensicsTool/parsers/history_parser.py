import sqlite3
import datetime
from pathlib import Path

class HistoryParser:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.db_path.name.lower()
        # All of these share the standard Chromium History schema
        if any(x in name for x in ["chrome", "edge", "brave", "opera"]):
            return "chrome_edge"
        elif "firefox" in name or "tor" in name:
            return "firefox"
        elif "safari" in name:
            return "safari"
        return "unknown"

    def _browser_label(self):
        name = self.db_path.name.lower()
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
        # WebKit epoch (microseconds since Jan 1, 1601)
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)
        except Exception:
            return ""

    def _firefox_time(self, timestamp):
        # PRTime epoch (microseconds since Jan 1, 1970)
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=timestamp)
        except Exception:
            return ""
        
    def _safari_time(self, timestamp):
        # CoreData epoch (seconds since Jan 1, 2001)
        if not timestamp:
            return ""
        try:
            return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=timestamp)
        except Exception:
            return ""

    def _chrome_transition_type(self, transition):
        # Chrome transition mapping
        types = {0: "Link", 1: "Typed", 2: "Auto Bookmark", 3: "Auto Subframe", 4: "Manual Subframe", 5: "Generated", 6: "Auto Toplevel", 7: "Form Submit", 8: "Reload"}
        core_type = transition & 0xFF if transition else 0
        return types.get(core_type, f"Unknown ({core_type})")

    def parse(self):
        if not self.db_path.exists():
            return []

        results = []
        try:
            # Need to open Safari dbs as read-only sometimes if live
            uri_path = f"file:{self.db_path.absolute()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            cursor = conn.cursor()

            if self.browser_type == "chrome_edge":
                # Advanced Chrome/Edge join across urls and visits
                query = """
                SELECT u.id, u.url, u.title, u.visit_count, u.hidden, 
                       v.visit_time, v.visit_duration, v.transition
                FROM urls u
                JOIN visits v ON u.id = v.url
                ORDER BY v.visit_time DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    u_id, url, title, count, hidden, v_time, duration, transition = row
                    results.append({
                        "Browser": self._browser_label(),
                        "Record ID": u_id,
                        "URL": url,
                        "Title": title,
                        "Visit Count": count,
                        "Hidden": "Yes" if hidden else "No",
                        "Last Visit Time": self._chrome_time(v_time),
                        "Visit Duration (secs)": (duration / 1000000.0) if duration else 0,
                        "Transition Type": self._chrome_transition_type(transition)
                    })

            elif self.browser_type == "firefox":
                query = """
                SELECT p.id, p.url, p.title, p.visit_count, p.hidden, 
                       v.visit_date, v.visit_type
                FROM moz_places p
                JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    p_id, url, title, count, hidden, v_time, v_type = row
                    results.append({
                        "Browser": self._browser_label(),
                        "Record ID": p_id,
                        "URL": url,
                        "Title": title,
                        "Visit Count": count,
                        "Hidden": "Yes" if hidden else "No",
                        "Last Visit Time": self._firefox_time(v_time),
                        "Visit Duration (secs)": "", # Firefox doesn't easily store duration here
                        "Transition Type": f"Type_{v_type}"
                    })
                    
            elif self.browser_type == "safari":
                query = """
                SELECT i.id, i.url, v.title, v.visit_time
                FROM history_items i
                LEFT JOIN history_visits v ON i.id = v.history_item
                ORDER BY v.visit_time DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    i_id, url, title, v_time = row
                    results.append({
                        "Browser": self._browser_label(),
                        "Record ID": i_id,
                        "URL": url,
                        "Title": title,
                        "Visit Count": "", 
                        "Hidden": "",
                        "Last Visit Time": self._safari_time(v_time),
                        "Visit Duration (secs)": "",
                        "Transition Type": ""
                    })
            conn.close()
        except sqlite3.Error as e:
            print(f"[-] SQLite Error reading history {self.db_path}: {e}")
            
        print(f"[+] Parsed {len(results)} extended history records from {self.db_path.name}.")
        return results
