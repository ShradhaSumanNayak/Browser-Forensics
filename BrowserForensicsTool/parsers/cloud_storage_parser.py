import os
import re
from urllib.parse import parse_qs, unquote, urlparse


class CloudStorageParser:
    def __init__(self):
        self.providers = [
            {
                "name": "Google Drive",
                "domains": [
                    "drive.google.com",
                    "drive.usercontent.google.com",
                    "docs.google.com",
                    "storage.googleapis.com",
                ],
                "cookie_tokens": ["sid", "g_state", "oauth", "sapisid", "ssid"],
            },
            {
                "name": "Microsoft OneDrive",
                "domains": [
                    "onedrive.live.com",
                    "1drv.ms",
                    "storage.live.com",
                    "sharepoint.com",
                    "sharepoint-df.com",
                ],
                "cookie_tokens": ["fedauth", "rtfa", "wlssc", "session", "auth"],
            },
            {
                "name": "Dropbox",
                "domains": [
                    "dropbox.com",
                    "dropboxusercontent.com",
                    "dropboxstatic.com",
                ],
                "cookie_tokens": ["sess", "token", "csrf", "lid"],
            },
            {
                "name": "Box",
                "domains": ["box.com", "boxcloud.com"],
                "cookie_tokens": ["auth", "session", "token", "visitor"],
            },
            {
                "name": "iCloud Drive",
                "domains": ["icloud.com"],
                "cookie_tokens": ["session", "auth", "token"],
            },
            {
                "name": "MEGA",
                "domains": ["mega.nz", "mega.io"],
                "cookie_tokens": ["sid", "session", "state"],
            },
            {
                "name": "pCloud",
                "domains": ["pcloud.com", "pcloud.link"],
                "cookie_tokens": ["auth", "session", "token"],
            },
            {
                "name": "MediaFire",
                "domains": ["mediafire.com"],
                "cookie_tokens": ["session", "auth", "token"],
            },
            {
                "name": "WeTransfer",
                "domains": ["wetransfer.com", "we.tl"],
                "cookie_tokens": ["session", "auth", "token"],
            },
        ]
        self.resource_query_keys = ["filename", "file", "name", "path", "id", "resid", "cid", "folder"]
        self.noise_segments = {
            "u",
            "my",
            "drive",
            "drives",
            "folders",
            "folder",
            "file",
            "files",
            "d",
            "s",
            "open",
            "view",
            "edit",
            "download",
            "preview",
            "shared",
            "sharing",
            "personal",
            "documents",
            "document",
            "spreadsheets",
            "presentation",
            "home",
        }

    def _normalize_host(self, value):
        host = str(value or "").strip().lower()
        if not host:
            return ""
        if "://" in host:
            host = urlparse(host).hostname or ""
        host = host.lstrip(".")
        return host

    def _match_provider_by_host(self, host):
        normalized_host = self._normalize_host(host)
        if not normalized_host:
            return None

        for provider in self.providers:
            for domain in provider["domains"]:
                if normalized_host == domain or normalized_host.endswith(f".{domain}"):
                    return provider
        return None

    def _match_provider_by_url(self, url):
        try:
            parsed = urlparse(str(url or ""))
        except Exception:
            return None
        return self._match_provider_by_host(parsed.hostname or "")

    def _extract_resource_hint(self, url, local_path=""):
        local_name = os.path.basename(str(local_path or "").replace("\\", "/"))
        if local_name:
            return local_name

        try:
            parsed = urlparse(str(url or ""))
        except Exception:
            return ""

        query = parse_qs(parsed.query)
        for key in self.resource_query_keys:
            value = query.get(key)
            if value and value[0]:
                return unquote(str(value[0]))

        segments = [unquote(segment) for segment in parsed.path.split("/") if segment]
        for segment in reversed(segments):
            clean = segment.strip().lower()
            if not clean or clean in self.noise_segments:
                continue
            if re.fullmatch(r"[a-z0-9_-]{1,3}", clean):
                continue
            return segment
        return ""

    def _infer_history_activity(self, url):
        lowered = str(url or "").lower()
        if any(token in lowered for token in ["download", "export=download", "download.aspx", "dl=1"]):
            return "Download"
        if any(token in lowered for token in ["upload", "uploads", "request/upload", "addfile"]):
            return "Upload"
        if any(token in lowered for token in ["share", "sharing", "shared", "guestaccess", "invite", "/s/"]):
            return "Share"
        if any(token in lowered for token in ["delete", "trash", "removed"]):
            return "Delete"
        if any(token in lowered for token in ["folder", "folders", "directory"]):
            return "Folder Access"
        return "Cloud File Activity"

    def _append_record(self, results, seen, record):
        signature = (
            record.get("Provider", ""),
            record.get("Browser", ""),
            record.get("Artifact Source", ""),
            record.get("Activity", ""),
            record.get("Timestamp", ""),
            record.get("URL", ""),
            record.get("Local Path", ""),
            record.get("Cookie Name", ""),
        )
        if signature in seen:
            return
        seen.add(signature)
        results.append(record)

    def parse(
        self,
        history_records=None,
        download_records=None,
        bookmark_records=None,
        cookie_records=None,
        session_records=None,
        storage_records=None,
    ):
        history_records = history_records or []
        download_records = download_records or []
        bookmark_records = bookmark_records or []
        cookie_records = cookie_records or []
        session_records = session_records or []
        storage_records = storage_records or []

        results = []
        seen = set()

        for rec in history_records:
            url = rec.get("URL", "")
            provider = self._match_provider_by_url(url)
            if not provider:
                continue
            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "History",
                    "Activity": self._infer_history_activity(url),
                    "Timestamp": rec.get("Last Visit Time", ""),
                    "URL": url,
                    "Resource Hint": self._extract_resource_hint(url),
                    "Local Path": "",
                    "Title / Name": rec.get("Title", ""),
                    "Cookie Name": "",
                    "Details": f"Transition={rec.get('Transition Type', '')}; Visits={rec.get('Visit Count', '')}",
                    "Confidence": "Medium",
                },
            )

        for rec in download_records:
            url = rec.get("Source URL", "")
            provider = self._match_provider_by_url(url)
            if not provider:
                continue
            target_path = rec.get("Target Path", "")
            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "Downloads",
                    "Activity": "Download",
                    "Timestamp": rec.get("Start Time", "") or rec.get("End Time", ""),
                    "URL": url,
                    "Resource Hint": self._extract_resource_hint(url, local_path=target_path),
                    "Local Path": target_path,
                    "Title / Name": "",
                    "Cookie Name": "",
                    "Details": f"State={rec.get('State', '')}; Size={rec.get('Total Bytes', '')}; MIME={rec.get('MIME Type', '')}",
                    "Confidence": "High",
                },
            )

        for rec in bookmark_records:
            url = rec.get("URL", "")
            provider = self._match_provider_by_url(url)
            if not provider:
                continue
            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "Bookmarks",
                    "Activity": "Bookmark",
                    "Timestamp": rec.get("Date Added", ""),
                    "URL": url,
                    "Resource Hint": self._extract_resource_hint(url),
                    "Local Path": "",
                    "Title / Name": rec.get("Name", ""),
                    "Cookie Name": "",
                    "Details": f"Folder={rec.get('Folder', '')}",
                    "Confidence": "Medium",
                },
            )

        for rec in session_records:
            url = rec.get("URL", "")
            provider = self._match_provider_by_url(url)
            if not provider:
                continue
            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "Sessions",
                    "Activity": "Active Session",
                    "Timestamp": "",
                    "URL": url,
                    "Resource Hint": self._extract_resource_hint(url),
                    "Local Path": "",
                    "Title / Name": rec.get("Title", ""),
                    "Cookie Name": "",
                    "Details": rec.get("Type", ""),
                    "Confidence": "Medium",
                },
            )

        for rec in cookie_records:
            provider = self._match_provider_by_host(rec.get("Domain", ""))
            if not provider:
                continue

            cookie_name = str(rec.get("Name", ""))
            lowered_name = cookie_name.lower()
            if not any(token in lowered_name for token in provider["cookie_tokens"]):
                continue

            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "Cookies",
                    "Activity": "Authenticated Session Cookie",
                    "Timestamp": rec.get("Creation Time", ""),
                    "URL": "",
                    "Resource Hint": "",
                    "Local Path": "",
                    "Title / Name": rec.get("Domain", ""),
                    "Cookie Name": cookie_name,
                    "Details": f"Path={rec.get('Path', '')}; Secure={rec.get('Secure', '')}; HTTPOnly={rec.get('HTTP Only', '')}",
                    "Confidence": "Low",
                },
            )

        for rec in storage_records:
            provider = self._match_provider_by_url(rec.get("URL Candidates", "")) or self._match_provider_by_host(
                rec.get("Origin / Scope", "")
            )
            if not provider:
                continue

            self._append_record(
                results,
                seen,
                {
                    "Provider": provider["name"],
                    "Browser": rec.get("Browser", "Unknown"),
                    "Artifact Source": "Browser Storage",
                    "Activity": rec.get("Evidence Type", "Browser Storage"),
                    "Timestamp": "",
                    "URL": rec.get("URL Candidates", "").split(" | ")[0] if rec.get("URL Candidates") else "",
                    "Resource Hint": rec.get("Key", "") or rec.get("Origin / Scope", ""),
                    "Local Path": rec.get("Source File", ""),
                    "Title / Name": rec.get("Origin / Scope", ""),
                    "Cookie Name": "",
                    "Details": f"{rec.get('Storage Category', '')}; {rec.get('Value Preview', '')[:150]}",
                    "Confidence": "Medium",
                },
            )

        return results
