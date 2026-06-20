import shutil
import sqlite3
import os
from pathlib import Path

def copy_resilient(source, target):
    """
    Law Enforcement Grade Resilient Copy:
    Attempts multiple strategies to capture a file, even if locked by a browser.
    1. Direct file copy (shutil.copy2)
    2. SQLite Backup API (if it's a database)
    3. Binary stream read (for non-exclusive locks)
    """
    source = Path(source)
    target = Path(target)
    
    # Strategy 1: Standard Copy
    try:
        shutil.copy2(source, target)
        return True
    except (PermissionError, OSError):
        pass # Handle lock in next strategies

    # Strategy 2: SQLite Backup (Aggressive)
    # Most browser artifacts are SQLite. We try even if the initial read fails.
    try:
        # Use a connection string that bypasses locking mechanisms where possible
        conn_str = f"file:{source.absolute()}?mode=ro&nolock=1"
        conn = sqlite3.connect(conn_str, uri=True)
        # Try a quick sanity check
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        
        backup_conn = sqlite3.connect(target)
        conn.backup(backup_conn)
        backup_conn.close()
        conn.close()
        return True
    except Exception:
        pass

    # Strategy 3: Raw Binary Stream Read (via OS level if possible)
    try:
        # On some systems, we can read even if locked if we share access
        # Python's open() with 'rb' usually attempts this, but we try one more time
        with open(source, 'rb', buffering=0) as f_src:
            with open(target, 'wb') as f_dst:
                shutil.copyfileobj(f_src, f_dst)
        return True
    except Exception:
        pass

    return False

def sanitize_path(path_str):
    """
    Harden paths against traversal and invalid characters.
    """
    if not path_str:
        return ""
    # Remove null bytes
    sanitized = str(path_str).replace('\x00', '')
    # Reject any relative traversal sequences to avoid accidental escapes
    if '..' in sanitized:
        return ""

    try:
        candidate = Path(sanitized).expanduser()
        candidate = candidate.resolve(strict=False)
        # Require an absolute resolved path
        if not candidate.is_absolute():
            return ""
        # Reject root-only or anchor-only output paths to avoid accidental system writes
        if candidate == candidate.anchor:
            return ""
        return str(candidate)
    except Exception:
        return ""

def export_physical_downloads(parsed_downloads, output_dir, logger_callback=None):
    """
    Safely copies physical documents referenced in download history to an export folder.
    """
    def log(msg):
        if logger_callback:
            logger_callback(msg)
        else:
            print(msg)
            
    if not parsed_downloads:
        return 0
        
    export_dir = Path(output_dir) / "exported_downloads"
    export_dir.mkdir(parents=True, exist_ok=True)
    
    exported_count = 0
    seen_filenames = set()
    
    for record in parsed_downloads:
        target_path = record.get("Target Path")
        if target_path and os.path.exists(target_path) and os.path.isfile(target_path):
            filename = os.path.basename(target_path)
            
            # Handle filename collisions
            base, ext = os.path.splitext(filename)
            counter = 1
            safe_filename = filename
            while safe_filename in seen_filenames:
                safe_filename = f"{base}_{counter}{ext}"
                counter += 1
                
            seen_filenames.add(safe_filename)
            safe_dest = export_dir / safe_filename
            
            try:
                # Use resilient copy in case the file is locked by a browser
                if copy_resilient(target_path, safe_dest):
                    exported_count += 1
                    # Log large files? (optional)
            except Exception as e:
                log(f"    [-] Failed to export {filename}: {e}")
                
    return exported_count

