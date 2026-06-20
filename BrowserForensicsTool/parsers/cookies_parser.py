import datetime
import sqlite3
import struct
from pathlib import Path


class CookiesParser:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.db_path.name.lower()
        if any(token in name for token in ["chrome", "edge", "brave", "opera"]):
            return "chromium"
        if "firefox" in name or "tor" in name:
            return "firefox"
        if "safari" in name and "binarycookies" in name:
            return "safari_binarycookies"
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
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=timestamp)
        except Exception:
            return ""

    def _safari_time(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=float(timestamp))
        except Exception:
            return ""

    def _read_c_string(self, blob, offset):
        if offset <= 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset)
        if end == -1:
            end = len(blob)
        return blob[offset:end].decode("utf-8", errors="ignore")

    def _parse_safari_binarycookies(self):
        results = []
        browser_name = self._browser_label()
        data = self.db_path.read_bytes()
        if not data.startswith(b"cook") or len(data) < 8:
            return results

        page_count = struct.unpack(">I", data[4:8])[0]
        page_sizes = []
        cursor = 8
        for _ in range(page_count):
            page_sizes.append(struct.unpack(">I", data[cursor:cursor + 4])[0])
            cursor += 4

        for page_size in page_sizes:
            page = data[cursor:cursor + page_size]
            cursor += page_size
            if len(page) < 8:
                continue

            cookie_count = struct.unpack("<I", page[4:8])[0]
            offset_start = 8
            if cookie_count == 0 or cookie_count > 5000:
                cookie_count = struct.unpack("<I", page[0:4])[0]
                offset_start = 4

            for idx in range(cookie_count):
                offset_pos = offset_start + (idx * 4)
                if offset_pos + 4 > len(page):
                    break
                cookie_offset = struct.unpack("<I", page[offset_pos:offset_pos + 4])[0]
                if cookie_offset + 56 > len(page):
                    continue

                cookie_size = struct.unpack("<I", page[cookie_offset:cookie_offset + 4])[0]
                cookie = page[cookie_offset:cookie_offset + cookie_size]
                if len(cookie) < 56:
                    continue

                try:
                    flags = struct.unpack("<I", cookie[8:12])[0]
                    domain_offset = struct.unpack("<I", cookie[16:20])[0]
                    name_offset = struct.unpack("<I", cookie[20:24])[0]
                    path_offset = struct.unpack("<I", cookie[24:28])[0]
                    value_offset = struct.unpack("<I", cookie[28:32])[0]
                    expires = struct.unpack("<d", cookie[40:48])[0]
                    created = struct.unpack("<d", cookie[48:56])[0]
                except struct.error:
                    continue

                results.append(
                    {
                        "Browser": browser_name,
                        "Domain": self._read_c_string(cookie, domain_offset),
                        "Name": self._read_c_string(cookie, name_offset),
                        "Path": self._read_c_string(cookie, path_offset),
                        "Value": self._read_c_string(cookie, value_offset),
                        "Creation Time": self._safari_time(created),
                        "Expiration Time": self._safari_time(expires),
                        "Secure": "Yes" if flags & 1 else "No",
                        "HTTP Only": "Yes" if flags & 4 else "No",
                        "SameSite": "",
                    }
                )

        return results

    def parse(self):
        if not self.db_path.exists():
            return []

        if self.browser_type == "safari_binarycookies":
            results = self._parse_safari_binarycookies()
            print(f"[+] Parsed {len(results)} cookies from {self.db_path.name}.")
            return results

        results = []
        try:
            uri_path = f"file:{self.db_path.absolute()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            cursor = conn.cursor()

            if self.browser_type == "chromium":
                browser_name = self._browser_label()
                try:
                    cursor.execute(
                        "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly, samesite, value FROM cookies"
                    )
                except sqlite3.Error:
                    cursor.execute(
                        "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly, 0, '' FROM cookies"
                    )
                for row in cursor.fetchall():
                    host, name, path, creation, expires, secure, httponly, samesite, value = row
                    results.append(
                        {
                            "Browser": browser_name,
                            "Domain": host,
                            "Name": name,
                            "Path": path,
                            "Value": value,
                            "Creation Time": self._chrome_time(creation),
                            "Expiration Time": self._chrome_time(expires),
                            "Secure": "Yes" if secure else "No",
                            "HTTP Only": "Yes" if httponly else "No",
                            "SameSite": samesite,
                        }
                    )

            elif self.browser_type == "firefox":
                cursor.execute(
                    "SELECT host, name, path, creationTime, expiry, isSecure, isHttpOnly, sameSite, value FROM moz_cookies"
                )
                for row in cursor.fetchall():
                    host, name, path, creation, expires, secure, httponly, samesite, value = row
                    results.append(
                        {
                            "Browser": self._browser_label(),
                            "Domain": host,
                            "Name": name,
                            "Path": path,
                            "Value": value,
                            "Creation Time": self._firefox_time(creation / 1000000 if creation else 0),
                            "Expiration Time": self._firefox_time(expires),
                            "Secure": "Yes" if secure else "No",
                            "HTTP Only": "Yes" if httponly else "No",
                            "SameSite": samesite,
                        }
                    )
            conn.close()
        except sqlite3.Error as e:
            print(f"[-] SQLite Error reading cookies {self.db_path}: {e}")

        print(f"[+] Parsed {len(results)} cookies from {self.db_path.name}.")
        return results
