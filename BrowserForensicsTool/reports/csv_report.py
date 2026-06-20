import csv
from pathlib import Path

class CSVReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, data, filename):
        if not data:
            # print(f"[-] No data provided for {filename}.")
            return False
            
        filepath = self.output_dir / filename
        
        # Get headers safely by iterating through all rows
        headers = []
        for row in data:
            for key in row.keys():
                if key not in headers:
                    headers.append(key)
        
        try:
            with open(filepath, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers, restval="", extrasaction="ignore")
                writer.writeheader()
                writer.writerows(data)
            print(f"[+] Successfully generated CSV report: {filepath}")
            return True
        except Exception as e:
            print(f"[-] Failed to generate CSV report: {e}")
            return False
