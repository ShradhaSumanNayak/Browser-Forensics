from pathlib import Path

class CacheReconstructor:
    """
    Forensic tool to reconstruct usable files from raw browser cache blobs.
    Identifies common file types using magic bytes (signatures) and 
    renames them with the correct extension.
    """
    # Expanded Magic Bytes Signatures
    SIGNATURES = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'GIF87a': '.gif',
        b'GIF89a': '.gif',
        b'%PDF': '.pdf',
        b'PK\x03\x04': '.zip', # Also DOCX/XLSX/PPTX
        b'RIFF': '.webp',
        b'\x49\x44\x33': '.mp3',
        b'<!DOCTYPE html': '.html',
        b'<html': '.html',
        b'BM': '.bmp',
        b'\x00\x00\x01\x00': '.ico',
        b'\x7fELF': '.elf',
        b'MZ': '.exe'
    }

    def __init__(self, cache_dir, reconstruction_dir):
        self.cache_dir = Path(cache_dir)
        self.reconstruction_dir = Path(reconstruction_dir)

    def reconstruct(self):
        """
        Iterates through the raw cache blobs and recovers files with known signatures.
        Handles Chromium SimpleCache format by searching bytes anywhere in the blob.
        """
        if not self.cache_dir.exists() or not self.cache_dir.is_dir():
            return 0
            
        self.reconstruction_dir.mkdir(parents=True, exist_ok=True)
        reconstructed_count = 0
        
        # Walk all files recursively to handle nested Cache_Data directories
        all_cache_files = [f for f in self.cache_dir.rglob("*") if f.is_file()]
        
        for entry in all_cache_files:
            try:
                with open(entry, "rb") as f:
                    # Read full file content to search anywhere for magic bytes
                    raw = f.read()
                    
                    # Try JPEG recovery (most common in web cache)
                    jpg_offsets = [i for i in range(min(len(raw), 5*1024*1024)) if raw[i:i+3] == b'\xff\xd8\xff']
                    for idx, offset in enumerate(jpg_offsets[:5]):
                        fragment_path = self.reconstruction_dir / f"{entry.stem}_{idx}.jpg"
                        with open(fragment_path, "wb") as out:
                            out.write(raw[offset:offset+500*1024])
                        reconstructed_count += 1
                        if reconstructed_count > 500:
                            break  # Safety cap
                    
                    # Try PNG recovery
                    if reconstructed_count < 500:
                        png_sig = b'\x89PNG\r\n\x1a\n'
                        png_offsets = [i for i in range(min(len(raw), 5*1024*1024)) if raw[i:i+8] == png_sig]
                        for idx, offset in enumerate(png_offsets[:5]):
                            fragment_path = self.reconstruction_dir / f"{entry.stem}_{idx}.png"
                            with open(fragment_path, "wb") as out:
                                out.write(raw[offset:offset+800*1024])
                            reconstructed_count += 1
                            if reconstructed_count > 500:
                                break
                    
                    # Direct signature match at start of file
                    if reconstructed_count < 500:
                        header = raw[:16]
                        for sig, ext in self.SIGNATURES.items():
                            if header.startswith(sig) and ext not in ('.jpg', '.png'):
                                target_path = self.reconstruction_dir / (entry.name + ext)
                                with open(target_path, "wb") as out:
                                    out.write(raw)
                                reconstructed_count += 1
                                break
                        
            except Exception:
                pass  # Silently skip unreadable blobs

        return reconstructed_count
