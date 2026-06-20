from pathlib import Path
import datetime

import pandas as pd


class TimelineGenerator:
    """
    Normalizes parsed browser artifacts into a single chronological timeline.
    """

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.timeline_events = []

    def _normalize_time(self, value):
        if value in ("", None, "N/A"):
            return None
        if hasattr(value, "to_pydatetime"):
            try:
                return pd.Timestamp(value)
            except Exception:
                return None
        if hasattr(value, "year") and hasattr(value, "month"):
            try:
                return pd.Timestamp(value)
            except Exception:
                return None
        # Handle numeric epoch values robustly (seconds, milliseconds, microseconds, WebKit microseconds)
        if isinstance(value, (int, float)):
            try:
                v = float(value)
                # Heuristics based on magnitude
                # WebKit microseconds since 1601 (~1.6e16 today)
                if v > 1e15:
                    return pd.Timestamp(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(v)))
                # Milliseconds since Unix epoch
                if v > 1e12:
                    return pd.Timestamp(datetime.datetime.fromtimestamp(v / 1000.0, datetime.UTC)).tz_localize(None)
                # Seconds since Unix epoch
                if v > 1e9:
                    return pd.Timestamp(datetime.datetime.fromtimestamp(v, datetime.UTC)).tz_localize(None)
                # Fallback: treat as seconds
                return pd.Timestamp(datetime.datetime.fromtimestamp(v, datetime.UTC)).tz_localize(None)
            except Exception:
                return None
        try:
            parsed = pd.to_datetime(value)
            if pd.isna(parsed):
                return None
            return parsed
        except Exception:
            return None

    def ingest_history(self, history_records):
        for rec in history_records:
            dt = self._normalize_time(rec.get("Last Visit Time"))
            if not dt:
                continue
            self.timeline_events.append(
                {
                    "Timestamp (UTC)": dt,
                    "Event Source": "Browsing History",
                    "Browser": rec.get("Browser", "Unknown"),
                    "URL / Target": rec.get("URL", ""),
                    "Details": (
                        f"Title: {rec.get('Title', '')} | "
                        f"Type: {rec.get('Transition Type', '')} | "
                        f"Duration: {rec.get('Visit Duration (secs)', '')}"
                    ),
                }
            )

    def ingest_downloads(self, download_records):
        for rec in download_records:
            dt = self._normalize_time(rec.get("Start Time"))
            end_dt = self._normalize_time(rec.get("End Time"))
            source_url = rec.get("Source URL", "")

            if dt:
                self.timeline_events.append(
                    {
                        "Timestamp (UTC)": dt,
                        "Event Source": "Download Started",
                        "Browser": rec.get("Browser", "Unknown"),
                        "URL / Target": source_url,
                        "Details": f"Target: {rec.get('Target Path', '')} | Size: {rec.get('Total Bytes', '')}",
                    }
                )
            if end_dt:
                self.timeline_events.append(
                    {
                        "Timestamp (UTC)": end_dt,
                        "Event Source": f"Download {rec.get('State', 'Ended')}",
                        "Browser": rec.get("Browser", "Unknown"),
                        "URL / Target": source_url,
                        "Details": f"Target: {rec.get('Target Path', '')}",
                    }
                )

    def ingest_cookies(self, cookie_records):
        for rec in cookie_records:
            dt = self._normalize_time(rec.get("Creation Time"))
            if not dt:
                continue
            self.timeline_events.append(
                {
                    "Timestamp (UTC)": dt,
                    "Event Source": "Cookie Created",
                    "Browser": rec.get("Browser", "Unknown"),
                    "URL / Target": f"Domain: {rec.get('Domain', '')}",
                    "Details": f"Name: {rec.get('Name', '')} | Secure: {rec.get('Secure', '')}",
                }
            )

    def ingest_passwords(self, password_records):
        for rec in password_records:
            dt = self._normalize_time(rec.get("Date Created"))
            last_used = self._normalize_time(rec.get("Date Last Used"))
            if dt:
                self.timeline_events.append(
                    {
                        "Timestamp (UTC)": dt,
                        "Event Source": "Credential Saved",
                        "Browser": rec.get("Browser", "Unknown"),
                        "URL / Target": rec.get("Origin URL", ""),
                        "Details": f"Username: {rec.get('Username', '')} | Status: {rec.get('Password Status', '')}",
                    }
                )
            if last_used:
                self.timeline_events.append(
                    {
                        "Timestamp (UTC)": last_used,
                        "Event Source": "Credential Used",
                        "Browser": rec.get("Browser", "Unknown"),
                        "URL / Target": rec.get("Origin URL", ""),
                        "Details": f"Username: {rec.get('Username', '')}",
                    }
                )

    def ingest_bookmarks(self, bookmark_records):
        for rec in bookmark_records:
            dt = self._normalize_time(rec.get("Date Added"))
            if not dt:
                continue
            self.timeline_events.append(
                {
                    "Timestamp (UTC)": dt,
                    "Event Source": "Bookmark Created",
                    "Browser": rec.get("Browser", "Unknown"),
                    "URL / Target": rec.get("URL", ""),
                    "Details": f"Title: {rec.get('Name', '')} | Folder: {rec.get('Folder', '')}",
                }
            )

    def ingest_forms(self, form_records):
        for rec in form_records:
            dt = self._normalize_time(rec.get("Date Created"))
            if not dt:
                continue
            self.timeline_events.append(
                {
                    "Timestamp (UTC)": dt,
                    "Event Source": f"Form/Search: {rec.get('Type', 'Entry')}",
                    "Browser": rec.get("Browser", "Unknown"),
                    "URL / Target": rec.get("Value", ""),
                    "Details": f"Field: {rec.get('Field Name', '')} | Count: {rec.get('Usage Count', '')}",
                }
            )

    def export_timeline(self):
        if not self.timeline_events:
            return None

        try:
            df = pd.DataFrame(self.timeline_events)
            df = df.sort_values(by="Timestamp (UTC)", ascending=True).reset_index(drop=True)
            if hasattr(df["Timestamp (UTC)"], "dt"):
                df["Timestamp (UTC)"] = df["Timestamp (UTC)"].dt.tz_localize(None)

            outfile = self.output_dir / "0_Forensic_Super_Timeline.xlsx"
            with pd.ExcelWriter(outfile, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Super Timeline")
                worksheet = writer.sheets["Super Timeline"]
                for idx, col in enumerate(df.columns):
                    series = df[col]
                    max_len = max(series.astype(str).map(len).max(), len(str(series.name))) + 2
                    worksheet.column_dimensions[worksheet.cell(row=1, column=idx + 1).column_letter].width = min(
                        max_len, 100
                    )
            return outfile
        except Exception as e:
            print(f"[-] Failed to generate Super Timeline: {e}")
            return None
