import re
from pathlib import Path

class SessionParser:
    """
    Extracts open tabs and session URLs from binary Current Session (Chromium) 
    and sessionstore.jsonlz4 (Firefox) files.
    """
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.file_path.name.lower()
        if "chrome" in name or "edge" in name or "brave" in name or "opera" in name:
            return "chrome_edge"
        elif "firefox" in name or "tor" in name:
            return "firefox"
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
        return "Unknown"

    def parse(self):
        if not self.file_path.exists():
            return []

        results = []
        try:
            content = self.file_path.read_bytes()
            
            if self.browser_type == "chrome_edge":
                # SNSS format is complex, but URLs are stored as UTF-8/UTF-16 strings
                # We'll use a regex to carve for likely URLs in the binary session file
                url_pattern = re.compile(rb'https?://[^\s\x00-\x1f\x7f-\xff]{5,500}')
                matches = url_pattern.findall(content)
                
                unique_urls = set()
                for m in matches:
                    url = m.decode('utf-8', errors='ignore')
                    if url not in unique_urls:
                        results.append({
                            "Browser": self._browser_label(),
                            "Type": "Open Tab / Session URL",
                            "URL": url,
                            "Title": "Restored from Session"
                        })
                        unique_urls.add(url)

            elif self.browser_type == "firefox":
                # Firefox sessionstore.jsonlz4
                # It starts with 'mozLz40\0', followed by uncompressed size, then lz4 block
                # Since we don't have a native lz4 decoder, we'll carve strings
                url_pattern = re.compile(rb'https?://[^\s"\'\x00-\x1f]{5,500}')
                matches = url_pattern.findall(content)
                
                unique_urls = set()
                for m in matches:
                    try:
                        url = m.decode('utf-8', errors='ignore')
                        # Sanitize URL end
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
