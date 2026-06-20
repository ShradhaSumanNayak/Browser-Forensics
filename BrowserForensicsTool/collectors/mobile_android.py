import subprocess
import shutil
from pathlib import Path

class AndroidBrowserCollector:
    """
    Forensically extracts browser data from Android devices via ADB.
    Requires ADB to be installed and 'USB Debugging' enabled on the target.
    Target paths: 
    - Chrome: /data/data/com.android.chrome/app_tabs/0/
    - Databases: /data/data/com.android.chrome/databases/
    """
    def __init__(self, output_dir, logger_callback=None):
        self.output_dir = Path(output_dir) / "mobile_android"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log = logger_callback if logger_callback else print

    def check_adb(self):
        """ Checks if ADB is available in the system path. """
        return shutil.which("adb") is not None

    def list_devices(self):
        """ Returns a list of connected ADB devices. """
        if not self.check_adb():
            return []
        try:
            output = subprocess.check_output(["adb", "devices"]).decode()
            lines = output.strip().split("\n")[1:]
            return [line.split("\t")[0] for line in lines if "\tdevice" in line]
        except Exception:
            return []

    def collect(self, device_id=None):
        """
        Attempts to pull Chrome/Browser artifacts from the device.
        Note: Accessing /data/data/ requires 'adb root' or a backup exploit.
        """
        devices = self.list_devices()
        if not devices:
            self.log("[-] No Android devices detected via ADB.")
            return False
        
        target_device = device_id if device_id else devices[0]
        self.log(f"[*] Attaching to device: {target_device}")
        
        # Common Android Browser Paths
        paths = [
            "/data/data/com.android.chrome/app_tabs/0/",
            "/data/data/com.android.chrome/databases/",
            "/data/data/com.android.chrome/cache/"
        ]
        
        success = False
        for remote_path in paths:
            local_name = remote_path.strip("/").replace("/", "_")
            dest = self.output_dir / local_name
            
            self.log(f"    -> Attempting to pull {remote_path}...")
            try:
                # Use ADB pull command
                cmd = ["adb", "-s", target_device, "pull", remote_path, str(dest)]
                result = subprocess.run(cmd, capture_output=True, timeout=60)
                
                if result.returncode == 0:
                    self.log(f"    [+] Successfully pulled {remote_path}")
                    success = True
                else:
                    self.log(f"    [-] Failed to pull {remote_path} (Permissions likely restricted)")
                    
            except Exception as e:
                self.log(f"    [-] ADB Error: {e}")
                
        return success

if __name__ == "__main__":
    collector = AndroidBrowserCollector("./test_mobile")
    if collector.check_adb():
        collector.collect()
