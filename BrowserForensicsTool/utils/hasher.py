import hashlib
import os
import threading
from pathlib import Path

_MANIFEST_LOCK = threading.Lock()

def generate_sha256(filepath):
    """
    Cryptographically hashes a file to prove its state has not been tampered with.
    Reads the file in blocks to prevent memory exhaustion on massive evidence files.
    """
    if not os.path.exists(filepath):
        return None

    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[-] Hashing Error for {filepath}: {e}")
        return None

def generate_directory_hashes(directory_path, base_name=None):
    """
    Recursively hashes all files in a collected evidence directory.
    """
    directory = Path(directory_path)
    if not directory.exists() or not directory.is_dir():
        return {}

    display_root = base_name or directory.name
    hashes = {}
    for file_path in sorted(path for path in directory.rglob("*") if path.is_file()):
        file_hash = generate_sha256(file_path)
        if not file_hash:
            continue
        relative_name = file_path.relative_to(directory).as_posix()
        hashes[f"{display_root}/{relative_name}"] = file_hash
    return hashes

def write_hash_manifest(output_dir, hash_dict, manifest_name="hash_manifest.txt"):
    """
    Creates an immutable manifest locking all generated hashes to their files.
    """
    manifest_path = Path(output_dir) / manifest_name
    try:
        with _MANIFEST_LOCK:
            with open(manifest_path, "a", encoding="utf-8") as f:
                for filename, file_hash in hash_dict.items():
                    if file_hash:
                        f.write(f"{file_hash}  {filename}\n")
        return True
    except Exception as e:
        print(f"[-] Critical Error writing manifest: {e}")
        return False
