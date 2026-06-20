import os
import shutil
import platform
from pathlib import Path

class WindowsSandboxGenerator:
    """
    Creates an isolated Windows Sandbox (.wsb) environment to safely detonate
    and analyze extracted download files that are suspected of being malware.
    Only supports Windows 10/11 Pro or Enterprise hosts with Sandbox enabled.
    """
    def __init__(self, output_dir, logger_callback=None):
        self.output_dir = Path(output_dir)
        self.quarantine_dir = self.output_dir / "quarantine"
        self.logger_callback = logger_callback

    def log(self, msg):
        if self.logger_callback:
            self.logger_callback(msg)
        else:
            print(msg)

    def quarantine_downloads(self, parsed_downloads):
        """
        Cross-references parsed SQLite download history and copies the physical files into isolation.
        """
        if platform.system() != "Windows":
             self.log("[-] Quarantine skipped. Windows required for WSB.")
             return 0
             
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        isolated_count = 0
        
        for download in parsed_downloads:
             target_path = download.get("Target Path")
             if target_path and os.path.exists(target_path):
                  filename = os.path.basename(target_path)
                  safe_path = self.quarantine_dir / filename
                  
                  # Only copy if we haven't already grabbed it (avoids loops)
                  if not safe_path.exists():
                       try:
                           self.log(f"    -> [!] QUARANTINING SUSPECT FILE: {filename}")
                           shutil.copy2(target_path, safe_path)
                           isolated_count += 1
                       except Exception as e:
                           self.log(f"    [-] Quarantine failure on {filename}: {e}")
                           
        return isolated_count

    def generate_wsb(self):
         """
         Creates the .wsb XML configuration mapping the quarantine folder to a secure, disposable VM.
         """
         if platform.system() != "Windows":
             return False
             
         wsb_path = self.output_dir / "Detonate_Malware_Sandbox.wsb"
         
         # WSB XML Configuration (Read-only mapped drive to protect host)
         wsb_content = f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{self.quarantine_dir.absolute()}</HostFolder>
      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\Quarantined_Evidence</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe C:\\Users\\WDAGUtilityAccount\\Desktop\\Quarantined_Evidence</Command>
  </LogonCommand>
</Configuration>
"""
         try:
             with open(wsb_path, "w", encoding="utf-8") as f:
                 f.write(wsb_content)
             self.log(f"[+] Sandbox Generated: {wsb_path}")
             self.log("[!] DANGER: Double-click Detonate_Malware_Sandbox.wsb to safely analyze files.")
             return True
         except Exception as e:
             self.log(f"[-] Failed to generate sandbox: {e}")
             return False
