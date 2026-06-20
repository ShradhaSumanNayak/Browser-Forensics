import json
from pathlib import Path

class PermissionsParser:
    """
    Parses Chromium 'Preferences' and 'Local State' files to extract Hardware Fingerprinting
    and Site Permission Grants (Camera, Microphone, Geolocation, Notifications).
    """

    def __init__(self, artifact_path):
        self.artifact_path = Path(artifact_path)
        self.browser = self._browser_label()

    def _browser_label(self):
        name = self.artifact_path.name.lower()
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

    def _parse_chromium_preferences(self, file_path):
        results = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            # E.g.: profile -> content_settings -> exceptions -> media_stream_mic
            # Different chromium versions store this slightly differently.
            
            content_settings = data.get("profile", {}).get("content_settings", {}).get("exceptions", {})
            
            # Map of internal setting keys to human readable
            target_keys = {
                "media_stream_mic": "Microphone",
                "media_stream_camera": "Camera",
                "geolocation": "Geolocation",
                "notifications": "Push Notifications",
                "usb_chooser_data": "USB Device Access",
                "serial_chooser_data": "Serial Port Access",
                "bluetooth_chooser_data": "Bluetooth Device Access"
            }

            for key, readable_name in target_keys.items():
                grants = content_settings.get(key, {})
                for site_url, setting in grants.items():
                    # Setting often contains { "setting": 1 (allow) or 2 (block), "last_modified": "132..." (webkit epoch) }
                    setting_dict = setting.get("setting", {}) if isinstance(setting, dict) else setting
                    last_used = setting.get("last_used", "") if isinstance(setting, dict) else ""
                    last_modified = setting.get("last_modified", "") if isinstance(setting, dict) else ""

                    # We log both allowed and blocked for forensic completeness
                    status = "Allowed" if setting_dict == 1 else ("Blocked" if setting_dict == 2 else f"Unknown({setting_dict})")

                    results.append({
                        "Browser": self.browser,
                        "Component": "Hardware/Permission Grant",
                        "Origin": site_url,
                        "Permission Type": readable_name,
                        "Status": status,
                        "Last Modified (Raw Webkit)": str(last_modified),
                        "Last Used (Raw Webkit)": str(last_used),
                        "Evidence File": file_path.name
                    })
                    
        except Exception:
            pass
        return results

    def _parse_webrtc_logs(self, file_path):
        results = []
        try:
            raw = file_path.read_text(encoding="utf-8", errors="ignore")
            # WebRTC Event Logs often expose ICE candidates containing local and public IPs
            import re
            candidates = re.findall(r"candidate:.*? (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*? typ (host|srflx|prflx|relay)", raw)
            for ip, typ in candidates:
                results.append({
                    "Browser": self.browser,
                    "Component": "WebRTC IP Leak",
                    "Origin": "WebRTC Event Log",
                    "Permission Type": f"ICE Candidate ({typ})",
                    "Status": "Exposed",
                    "Last Modified (Raw Webkit)": "N/A",
                    "Last Used (Raw Webkit)": "N/A",
                    "Evidence File": f"WebRTC Log ({ip})"
                })
        except Exception:
            pass
        return results

    def parse(self):
        if not self.artifact_path.exists() or not self.artifact_path.is_dir():
            return []

        results = []
        files = list(self.artifact_path.rglob("*"))

        for file_path in files:
            if not file_path.is_file():
                continue
                
            name = file_path.name.lower()
            
            # Browser Preferences
            if name in ["preferences", "secure preferences", "local state"]:
                results.extend(self._parse_chromium_preferences(file_path))
                
            # WebRTC event logs (often bare files in webrtc_event_logs folder)
            if "webrtc" in file_path.parts or name.startswith("webrtc"):
                results.extend(self._parse_webrtc_logs(file_path))

        return results
