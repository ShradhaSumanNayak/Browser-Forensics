import hashlib
import sys
import os
from pathlib import Path

def get_tool_hash():
    """
    Generates a SHA-256 hash of the tool's core logic files.
    Used for LEA Self-Integrity verification.
    """
    hasher = hashlib.sha256()

    if getattr(sys, "frozen", False):
        executable_path = Path(sys.executable)
        try:
            with open(executable_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "INTEGRITY_CHECK_FAILED"

    root_dir = Path(__file__).parent.parent
    
    # Broad integrity check: main tool, all collectors, and all parsers
    target_paths = [root_dir / "main.py"]
    
    # Add all collectors
    coll_dir = root_dir / "collectors"
    if coll_dir.exists():
        target_paths.extend(sorted(coll_dir.glob("*.py")))
        
    # Add all parsers
    pars_dir = root_dir / "parsers"
    if pars_dir.exists():
        target_paths.extend(sorted(pars_dir.glob("*.py")))
        
    # Add core utils
    util_dir = root_dir / "utils"
    if util_dir.exists():
        target_paths.append(util_dir / "io_helper.py")
        target_paths.append(util_dir / "integrity.py")
    
    try:
        for path in target_paths:
            if path.exists():
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
        if hasher.digest_size and hasher.hexdigest():
            return hasher.hexdigest()
        return "INTEGRITY_CHECK_FAILED"
    except Exception:
        return "INTEGRITY_CHECK_FAILED"

def verify_environment():
    """
    Checks for administrator/root privileges and environment security.
    """
    is_admin = False
    try:
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0
    except Exception:
        pass
    
    return {
        "is_admin": is_admin,
        "platform": sys.platform,
        "python_version": sys.version.split()[0]
    }
