import datetime
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import uuid
from pathlib import Path

try:
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Signature import DSS

    SIGNING_AVAILABLE = True
except ImportError:
    SIGNING_AVAILABLE = False


def _json_serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    return str(obj)


class ChainOfCustody:
    """
    Portable chain-of-custody signer based on a persistent ECC keypair.
    """

    def __init__(self, key_dir=None):
        default_dir = Path(os.getenv("BFT_CUSTODY_KEY_DIR", Path.home() / ".browser_forensics" / "keys"))
        self.key_dir = Path(key_dir) if key_dir else default_dir
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.private_key_path = self.key_dir / "chain_of_custody_private.pem"
        self.public_key_path = self.key_dir / "chain_of_custody_public.pem"
        self.device_info = self._get_device_identifiers()
        self.private_key = None
        self.public_key = None
        self.key_id = "unsigned"
        self.algorithm = "sha3-256-fallback"
        self._load_or_create_keys()

    def _load_or_create_keys(self):
        if not SIGNING_AVAILABLE:
            return

        if self.private_key_path.exists() and self.public_key_path.exists():
            self.private_key = ECC.import_key(self.private_key_path.read_text(encoding="utf-8"))
            self.public_key = ECC.import_key(self.public_key_path.read_text(encoding="utf-8"))
        else:
            self.private_key = ECC.generate(curve="P-256")
            self.public_key = self.private_key.public_key()
            
            # Write private key with secure permissions (owner R/W only)
            if os.name == 'nt':
                 # Windows-friendly way: write then potentially use cacls if needed, 
                 # but for cross-platform consistency we write normally first
                 self.private_key_path.write_text(self.private_key.export_key(format="PEM"), encoding="utf-8")
            else:
                 # POSIX: create with 0600
                 with os.fdopen(os.open(self.private_key_path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
                     f.write(self.private_key.export_key(format="PEM"))
            
            self.public_key_path.write_text(self.public_key.export_key(format="PEM"), encoding="utf-8")

        public_der = self.public_key.export_key(format="DER")
        self.key_id = hashlib.sha256(public_der).hexdigest()[:16]
        self.algorithm = "ecdsa-p256-sha256"

    def _get_device_identifiers(self):
        identifiers = {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "mac": ":".join(
                ["{:02x}".format((uuid.getnode() >> offset) & 0xFF) for offset in range(0, 8 * 6, 8)][::-1]
            ),
            "python_version": platform.python_version(),
            "disk_serial": "N/A",
        }

        if platform.system() == "Windows":
            try:
                output = subprocess.check_output("wmic diskdrive get serialnumber", shell=True, text=True)
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                if len(lines) > 1:
                    identifiers["disk_serial"] = lines[1]
            except Exception:
                pass
        return identifiers

    def export_public_key(self, destination_dir):
        if not self.public_key_path.exists():
            return None
        destination = Path(destination_dir)
        destination.mkdir(parents=True, exist_ok=True)
        exported = destination / "chain_of_custody_public.pem"
        if not exported.exists():
            shutil.copy2(self.public_key_path, exported)
        return exported

    def sign_log_entry(self, entry_data):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "timestamp": timestamp,
            "device": self.device_info,
            "data": entry_data,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, default=_json_serial).encode("utf-8")

        if SIGNING_AVAILABLE and self.private_key:
            digest = SHA256.new(payload_bytes)
            signer = DSS.new(self.private_key, "fips-186-3")
            signature = signer.sign(digest).hex()
            return {
                "payload": payload,
                "signature": signature,
                "algorithm": self.algorithm,
                "key_id": self.key_id,
            }

        fallback_sig = hashlib.sha3_256(payload_bytes).hexdigest()
        return {
            "payload": payload,
            "signature": fallback_sig,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
        }

    def verify_log_entry(self, signed_entry, public_key_path=None):
        payload_bytes = json.dumps(signed_entry["payload"], sort_keys=True, default=_json_serial).encode("utf-8")
        algorithm = signed_entry.get("algorithm", "")
        signature = signed_entry.get("signature", "")

        if algorithm == "ecdsa-p256-sha256" and SIGNING_AVAILABLE:
            key_path = Path(public_key_path) if public_key_path else self.public_key_path
            public_key = ECC.import_key(Path(key_path).read_text(encoding="utf-8"))
            verifier = DSS.new(public_key, "fips-186-3")
            try:
                verifier.verify(SHA256.new(payload_bytes), bytes.fromhex(signature))
                return True
            except Exception:
                return False

        recalculated = hashlib.sha3_256(payload_bytes).hexdigest()
        return recalculated == signature

    def verify_log_file(self, log_file, public_key_path=None):
        log_path = Path(log_file)
        if not log_path.exists():
            return False
        try:
            with open(log_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    if not self.verify_log_entry(json.loads(line), public_key_path=public_key_path):
                        return False
        except Exception:
            return False
        return True


def log_custody_event(log_file, event_type, details, investigator="Unknown"):
    coc = ChainOfCustody()
    event_data = {
        "event": event_type,
        "details": details,
        "investigator": investigator,
    }

    signed = coc.sign_log_entry(event_data)
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    coc.export_public_key(log_path.parent)

    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(signed, default=_json_serial) + "\n")


if __name__ == "__main__":
    coc_log = "test_chain_of_custody.jsonl"
    log_custody_event(coc_log, "Tool Startup", "Forensic tool initialized by analyst", "Officer Doe")
    print(f"[+] Custody event logged to {coc_log}")
