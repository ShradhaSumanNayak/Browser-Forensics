import re
from pathlib import Path

class RecoveryParser:
    """
    Forensic recovery tool that carves deleted data from SQLite sidecar files (-wal, -shm).
    Uses regex patterns to find URLs, email addresses, and timestamps in unallocated 
    or uncommitted database pages.
    """
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        # Regex for common forensic artifacts
        # 1. URLs (History)
        self.url_pattern = re.compile(rb'https?://[a-zA-Z0-9\-\.\/\_\?\&\=\%\#\:]+')
        # 2. Emails (Forms/Autofill)
        self.email_pattern = re.compile(rb'[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}')
        # 3. Private Browsing Keywords & Internal Markers
        self.private_keywords = [
            b'incognito', b'private-browsing', b'inprivate', b'is_private:1', b'mode:private',
            b'ephemeral_storage', b'is_ephemeral', b'off_the_record', b'is_incognito',
            b'private_session', b'guest_mode', b'otr_context'
        ]
        # 4. Possible SQLite Row fragments & Search Queries
        self.search_terms = [
            b'google.com/search?q=', b'bing.com/search?q=', b'duckduckgo.com/?q=', 
            b'facebook.com', b'twitter.com', b'linkedin.com', b'youtube.com/results?search_query='
        ]

    def detect_portable_browser(self, data):
        """
        Scans binary data for signatures of portable browser launchers or configs.
        """
        portable_signatures = [b'FirefoxPortable', b'ChromePortable', b'Brave-Browser-Portable', b'OperaPortable', b'TorBrowser-Portable']
        findings = []
        for sig in portable_signatures:
            if sig in data:
                findings.append(sig.decode('utf-8'))
        return findings

    def parse(self):
        """
        Reads the file as binary and carves for recognizable patterns.
        """
        results = []
        if not self.file_path.exists():
            return results

        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()

            # 0. Portable Browser Check
            portable_hits = self.detect_portable_browser(data)
            for hit in portable_hits:
                results.append({
                    "Category": "Portable Browser Signature",
                    "Source File": self.file_path.name,
                    "Data": f"Found signature of {hit} in artifact.",
                    "Confidence": "High"
                })

            # 1. Carve URLs
            urls = self.url_pattern.findall(data)
            for url in set(urls):
                url_str = url.decode('utf-8', errors='ignore')
                if len(url_str) > 10: 
                    # Tag potential private browsing hits
                    category = "Deleted/Uncommitted URL"
                    if any(k in url_str.lower().encode() for k in self.private_keywords):
                        category = "POTENTIAL PRIVATE BROWSING URL"
                    
                    results.append({
                        "Category": category,
                        "Source File": self.file_path.name,
                        "Data": url_str,
                        "Confidence": "Low (Carved)"
                    })

            # 2. Carve Emails
            emails = self.email_pattern.findall(data)
            for email in set(emails):
                results.append({
                    "Category": "Deleted/Uncommitted Email",
                    "Source File": self.file_path.name,
                    "Data": email.decode('utf-8', errors='ignore'),
                    "Confidence": "Low (Carved)"
                })

            # 3. Carve Search Terms and Private Keywords
            for term in self.search_terms + self.private_keywords:
                matches = re.finditer(term, data)
                for m in matches:
                    start = max(0, m.start() - 20)
                    snippet = data[start:start+120].split(b'\x00')[0]
                    snippet_str = snippet.decode('utf-8', errors='ignore')
                    results.append({
                        "Category": "Deleted/Uncommitted Sensitive Fragment",
                        "Source File": self.file_path.name,
                        "Data": snippet_str,
                        "Confidence": "Medium (Carved)"
                    })

        except Exception as e:
            print(f"    [-] Recovery carving error on {self.file_path.name}: {e}")

        return results
