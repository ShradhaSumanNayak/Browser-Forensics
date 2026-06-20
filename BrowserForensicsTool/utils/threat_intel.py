import base64
import datetime

import requests


class ThreatIntel:
    """
    Integrates with public Threat Intelligence APIs.
    Currently supports VirusTotal URL lookups when VT_API_KEY is provided.
    """

    def __init__(self, vt_api_key=None):
        self.vt_api_key = vt_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3/urls"

    def _url_id(self, url):
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")

    def check_url_vt(self, url):
        if not self.vt_api_key:
            return {"status": "skipped", "message": "API Key Missing"}

        headers = {"x-apikey": self.vt_api_key}
        try:
            response = requests.get(f"{self.vt_base_url}/{self._url_id(url)}", headers=headers, timeout=20)
            if response.status_code == 404:
                submit = requests.post(self.vt_base_url, data={"url": url}, headers=headers, timeout=20)
                submit.raise_for_status()
                return {"status": "submitted", "message": "URL submitted for analysis"}

            response.raise_for_status()
            payload = response.json().get("data", {}).get("attributes", {})
            stats = payload.get("last_analysis_stats", {})
            last_analysis_date = payload.get("last_analysis_date")
            if last_analysis_date:
                last_analysis_date = datetime.datetime.utcfromtimestamp(last_analysis_date)

            return {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "last_analysis_date": last_analysis_date,
            }
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}

    def check_phishtank(self, url):
        return False


class AnomalyDetector:
    """
    Behavioral profiling to detect suspicious browser usage patterns.
    """

    def __init__(self):
        self.dark_web_keywords = ["onion", "tor2web", "darknet", "marketplace", "silkroad", "escrow"]
        self.phishing_keywords = ["login-verify", "secure-account", "update-credentials", "banking-security"]

    def analyze_history(self, history_data):
        findings = []
        for entry in history_data:
            url = str(entry.get("URL") or "").lower()

            if any(keyword in url for keyword in self.dark_web_keywords):
                findings.append({"Type": "Dark Web Anomaly", "Evidence": url, "Risk": "High"})

            if any(keyword in url for keyword in self.phishing_keywords):
                findings.append({"Type": "Suspicious Keyword/Phishing", "Evidence": url, "Risk": "Medium"})

        return findings

    def detect_spikes(self, history_data):
        return []
