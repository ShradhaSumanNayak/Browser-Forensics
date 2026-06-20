import re
from pathlib import Path

from parsers.browser_detection import browser_label, detect_browser, is_chromium, is_firefox_family


class SessionParser:
    """
    Extracts open tabs and session URLs from binary Current Session (Chromium)
    and sessionstore.jsonlz4 (Firefox) files.
    """

    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.browser = detect_browser(self.file_path.name)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        if is_chromium(self.browser):
            return "chrome_edge"
        if is_firefox_family(self.browser):
            return "firefox"
        return "unknown"

    def _browser_label(self):
        return browser_label(browser=self.browser)

    def parse(self):
        if not self.file_path.exists():
            return []

        results = []
        try:
            content = self.file_path.read_bytes()

            if self.browser_type == "chrome_edge":
                url_pattern = re.compile(rb'https?://[^\s\x00-\x1f\x7f-\xff]{5,500}')
                matches = url_pattern.findall(content)

                unique_urls = set()
                for match in matches:
                    url = match.decode("utf-8", errors="ignore")
                    if url not in unique_urls:
                        results.append({
                            "Browser": self._browser_label(),
                            "Type": "Open Tab / Session URL",
                            "URL": url,
                            "Title": "Restored from Session"
                        })
                        unique_urls.add(url)

            elif self.browser_type == "firefox":
                url_pattern = re.compile(rb'https?://[^\s"\'\x00-\x1f]{5,500}')
                matches = url_pattern.findall(content)

                unique_urls = set()
                for match in matches:
                    try:
                        url = match.decode("utf-8", errors="ignore")
                        url = re.split(r'[\\"]', url)[0]
                        if url not in unique_urls and len(url) > 10:
                            results.append({
                                "Browser": self._browser_label(),
                                "Type": "Session URL",
                                "URL": url,
                                "Title": "Extracted from LZ4 Session"
                            })
                            unique_urls.add(url)
                    except Exception:
                        continue

        except Exception as e:
            print(f"[-] Error parsing sessions from {self.file_path}: {e}")

        print(f"[+] Carved {len(results)} potential session URLs from {self.file_path.name}.")
        return results
