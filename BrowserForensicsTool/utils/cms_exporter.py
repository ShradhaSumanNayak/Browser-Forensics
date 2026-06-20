import json
import csv
import datetime
from pathlib import Path

class CMSExporter:
    """
    Exports forensic artifacts to formats compatible with Case Management Systems (CMS).
    Supports JSON (NIST DERD style) and specialized CSV for AXIOM/FTK ingest.
    """
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir) / "cms_export"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_to_nist__derd(self, all_data):
        """
        Generates a JSON package following Digital Evidence Reference Dataset principles.
        """
        def json_serial(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
            return str(obj)

        output_file = self.output_dir / "nist_derd_evidence_package.json"
        package = {
            "version": "1.0",
            "schema": "ForensicBrowserSuite_DERD_v1",
            "artifacts": all_data
        }
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=4, default=json_serial)
        
        return output_file

    def export_for_axiom(self, all_history):
        """
        Generates a tab-separated or specialized CSV commonly used for 3rd party tool input.
        """
        output_file = self.output_dir / "axiom_compatible_history.csv"
        if not all_history:
            return None
        # Compute headers from all rows to avoid missing keys
        headers = []
        for row in all_history:
            for k in row.keys():
                if k not in headers:
                    headers.append(k)
        with open(output_file, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_history)
            
        return output_file
