import re
from pathlib import Path

class ByteCarver:
    """
    Advanced forensic carving engine that scavenges deleted files from raw data.
    Uses header/footer signatures (Magic Bytes) to reconstruct file fragments.
    """
    def __init__(self, output_dir, logger_callback=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_callback = logger_callback
        
        # Professional Forensic Signatures
        self.signatures = {
            'jpg': {
                'header': b'\xFF\xD8\xFF',
                'footer': b'\xFF\xD9',
                'max_size': 10 * 1024 * 1024 # 10MB limit per image
            },
            'png': {
                'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
                'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
                'max_size': 15 * 1024 * 1024
            },
            'pdf': {
                'header': b'%PDF-',
                'footer': b'%%EOF',
                'max_size': 50 * 1024 * 1024
            },
            'sqlite': {
                'header': b'SQLite format 3\x00',
                'footer': None, # SQLite doesn't have a fixed footer; carve fixed block or until page end
                'fixed_size': 65536 # Grab 64KB fragments of potential DB pages
            }
        }

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def carve(self, raw_data, source_name="unknown_source"):
        """
        Scans byte stream for registered signatures and extracts file fragments.
        """
        carved_count = 0
        total_found = []

        for ext, sig in self.signatures.items():
            header = sig['header']
            footer = sig.get('footer')
            
            # Find all header offsets
            header_offsets = [m.start() for m in re.finditer(re.escape(header), raw_data)]
            
            for i, start_offset in enumerate(header_offsets):
                file_data = None
                
                if footer:
                    # Look for the immediate next footer after this header
                    footer_match = re.search(re.escape(footer), raw_data[start_offset:])
                    if footer_match:
                        end_offset = start_offset + footer_match.end()
                        size = end_offset - start_offset
                        
                        if size <= sig['max_size']:
                            file_data = raw_data[start_offset:end_offset]
                else:
                    # Fixed size carving (for formats without footers like DB pages)
                    size = sig.get('fixed_size', 4096)
                    file_data = raw_data[start_offset:start_offset+size]

                if file_data:
                    carved_count += 1
                    filename = f"carved_{source_name}_{carved_count}.{ext}"
                    filepath = self.output_dir / filename
                    
                    try:
                        with open(filepath, 'wb') as f:
                            f.write(file_data)
                        
                        total_found.append({
                            "Category": f"Carved {ext.upper()} File",
                            "Source File": source_name,
                            "Data": f"Recovered {len(file_data)} bytes to {filename}",
                            "Confidence": "Medium (Carved)"
                        })
                    except Exception as e:
                        self.log(f"    [-] Carving write error on {filename}: {e}")

        return total_found

    def carve_file(self, file_path):
        """
        Reads a physical file (e.g. .wal or raw image) and carves it.
        """
        p = Path(file_path)
        if not p.exists():
            return []
            
        try:
            with open(p, 'rb') as f:
                data = f.read()
            return self.carve(data, p.name)
        except Exception as e:
            self.log(f"    [-] Failed to read {p.name} for carving: {e}")
            return []
