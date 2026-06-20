import base64
import datetime
import hashlib
import hmac
import json
import platform
import sqlite3
import os
from pathlib import Path

# Try to import Windows Crypto libraries (will fail gracefully on Linux/macOS)
try:
    import win32crypt
    from Cryptodome.Cipher import AES, DES3

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class PasswordsParser:
    """
    Parses browser credential stores.
    - Chromium browsers use Login Data SQLite databases.
    - Firefox/Tor use logins.json plus key databases.
    """

    def __init__(self, db_path, local_state_path=None, key_db_path=None, master_password=""):
        self.db_path = Path(db_path)
        self.local_state_path = Path(local_state_path) if local_state_path else None
        self.key_db_path = Path(key_db_path) if key_db_path else None
        self.secret_key = None
        self.master_password = master_password or os.getenv("FIREFOX_MASTER_PASSWORD", "")
        self.firefox_sdr_key = None
        self.browser_type = self._detect_browser_type()

    def _detect_browser_type(self):
        name = self.db_path.name.lower()
        if name.endswith("logins.json") and any(token in name for token in ["firefox", "tor"]):
            return "firefox"
        return "chromium"

    def _browser_label(self):
        name = self.db_path.name.lower()
        if "chrome" in name:
            return "Chrome"
        if "edge" in name:
            return "Edge"
        if "brave" in name:
            return "Brave"
        if "opera" in name:
            return "Opera"
        if "tor" in name:
            return "Tor"
        if "firefox" in name:
            return "Firefox"
        return "Unknown"

    def _chrome_time(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(timestamp))
        except Exception:
            return ""

    def _firefox_time_ms(self, timestamp):
        if not timestamp:
            return ""
        try:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=int(timestamp))
        except Exception:
            return ""

    def _pkcs7_unpad(self, value):
        if not value:
            return value
        pad_len = value[-1]
        if pad_len < 1 or pad_len > 16:
            return value
        if value[-pad_len:] != bytes([pad_len]) * pad_len:
            return value
        return value[:-pad_len]

    def _read_der_length(self, data, offset):
        first = data[offset]
        offset += 1
        if first < 0x80:
            return first, offset
        count = first & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        return length, offset + count

    def _decode_oid(self, value):
        if not value:
            return ""
        first = value[0]
        oid_parts = [str(first // 40), str(first % 40)]
        current = 0
        for byte in value[1:]:
            current = (current << 7) | (byte & 0x7F)
            if not byte & 0x80:
                oid_parts.append(str(current))
                current = 0
        return ".".join(oid_parts)

    def _parse_der(self, data, offset=0):
        tag = data[offset]
        length, cursor = self._read_der_length(data, offset + 1)
        value = data[cursor:cursor + length]
        end = cursor + length
        node = {"tag": tag, "value": value, "children": []}
        if tag == 0x30:
            inner = 0
            while inner < len(value):
                child, inner_end = self._parse_der(value, inner)
                node["children"].append(child)
                inner = inner_end
        elif tag == 0x06:
            node["oid"] = self._decode_oid(value)
        elif tag == 0x02:
            node["int"] = int.from_bytes(value, "big")
        elif tag == 0x04:
            node["bytes"] = value
        return node, end

    def _first_octet(self, node):
        if node.get("tag") == 0x04:
            return node.get("bytes", b"")
        for child in node.get("children", []):
            value = self._first_octet(child)
            if value:
                return value
        return b""

    def _all_octets(self, node):
        values = []
        if node.get("tag") == 0x04:
            values.append(node.get("bytes", b""))
        for child in node.get("children", []):
            values.extend(self._all_octets(child))
        return values

    def _extract_pbe_params(self, der_bytes):
        root, _ = self._parse_der(der_bytes)
        if len(root["children"]) < 2:
            return None

        alg = root["children"][0]
        cipher_node = root["children"][1]
        cipher_text = cipher_node.get("bytes", b"")

        oid = ""
        params_node = None
        if alg.get("tag") == 0x30 and len(alg["children"]) >= 2:
            oid = alg["children"][0].get("oid", "")
            params_node = alg["children"][1]

        return {"oid": oid, "params": params_node, "cipher_text": cipher_text, "root": root}

    def _decrypt_moz_3des(self, global_salt, master_password, entry_salt, cipher_text):
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptographic backend unavailable")

        master_password = master_password.encode("utf-8")
        hp = hashlib.sha1(global_salt + master_password).digest()
        chp = hashlib.sha1(hp + entry_salt).digest()
        
        # Correct KDF pattern for NSS/3DES
        padded_entry_salt = entry_salt.ljust(20, b"\x00")
        k1 = hmac.new(chp, padded_entry_salt + entry_salt, hashlib.sha1).digest()
        tk = hmac.new(chp, padded_entry_salt, hashlib.sha1).digest()
        k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
        
        key_material = k1 + k2
        key = DES3.adjust_key_parity(key_material[:24])
        iv = key_material[24:32]
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return self._pkcs7_unpad(cipher.decrypt(cipher_text))

    def _decrypt_pbes2(self, global_salt, master_password, params_node, cipher_text):
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptographic backend unavailable")
        if not params_node or len(params_node.get("children", [])) < 2:
            raise ValueError("Invalid PBES2 parameters")

        kdf_node = params_node["children"][0]
        enc_node = params_node["children"][1]
        if len(kdf_node.get("children", [])) < 2 or len(enc_node.get("children", [])) < 2:
            raise ValueError("Incomplete PBES2 structure")

        kdf_params = kdf_node["children"][1]
        kdf_children = kdf_params.get("children", [])
        salt = kdf_children[0].get("bytes", b"") if kdf_children else b""
        iterations = kdf_children[1].get("int", 1) if len(kdf_children) > 1 else 1
        key_length = kdf_children[2].get("int", 32) if len(kdf_children) > 2 and "int" in kdf_children[2] else 32
        prf_hash = "sha1"
        if len(kdf_children) > 3:
            prf_oid = kdf_children[3]["children"][0].get("oid", "")
            if prf_oid == "1.2.840.113549.2.9":
                prf_hash = "sha256"
            elif prf_oid == "1.2.840.113549.2.11":
                prf_hash = "sha512"

        enc_oid = enc_node["children"][0].get("oid", "")
        iv = enc_node["children"][1].get("bytes", b"")
        base_secret = hashlib.sha1(global_salt + master_password.encode("utf-8")).digest()
        derived_key = hashlib.pbkdf2_hmac(prf_hash, base_secret, salt, iterations, dklen=key_length)

        if enc_oid == "2.16.840.1.101.3.4.1.2":
            cipher = AES.new(derived_key[:16], AES.MODE_CBC, iv)
        elif enc_oid == "2.16.840.1.101.3.4.1.22":
            cipher = AES.new(derived_key[:24], AES.MODE_CBC, iv)
        else:
            cipher = AES.new(derived_key[:32], AES.MODE_CBC, iv)
        return self._pkcs7_unpad(cipher.decrypt(cipher_text))

    def _extract_firefox_sdr_key(self):
        if not self.key_db_path or not self.key_db_path.exists():
            return None
        if not CRYPTO_AVAILABLE:
            return None
        if self.key_db_path.suffix.lower() != ".db" or self.key_db_path.name.lower() != "key4.db":
            return None

        try:
            conn = sqlite3.connect(f"file:{self.key_db_path.absolute()}?mode=ro", uri=True)
            cursor = conn.cursor()
            global_salt, password_check = cursor.execute(
                "SELECT item1, item2 FROM metadata WHERE id = 'password'"
            ).fetchone()
            private_blob = cursor.execute("SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL").fetchone()
            conn.close()
        except Exception as e:
            print(f"    [-] Error reading Firefox key database {self.key_db_path.name}: {e}")
            return None

        if not private_blob:
            return None

        try:
            password_pbe = self._extract_pbe_params(password_check)
            if not password_pbe:
                return None

            if password_pbe["oid"] == "1.2.840.113549.1.12.5.1.3":
                entry_salt = password_pbe["params"]["children"][0].get("bytes", b"")
                validation = self._decrypt_moz_3des(global_salt, self.master_password, entry_salt, password_pbe["cipher_text"])
            elif password_pbe["oid"] == "1.2.840.113549.1.5.13":
                validation = self._decrypt_pbes2(global_salt, self.master_password, password_pbe["params"], password_pbe["cipher_text"])
            else:
                return None

            if b"password-check" not in validation:
                return None

            key_blob = private_blob[0]
            key_pbe = self._extract_pbe_params(key_blob)
            if not key_pbe:
                return None

            if key_pbe["oid"] == "1.2.840.113549.1.12.5.1.3":
                entry_salt = key_pbe["params"]["children"][0].get("bytes", b"")
                decrypted_key = self._decrypt_moz_3des(global_salt, self.master_password, entry_salt, key_pbe["cipher_text"])
            elif key_pbe["oid"] == "1.2.840.113549.1.5.13":
                decrypted_key = self._decrypt_pbes2(global_salt, self.master_password, key_pbe["params"], key_pbe["cipher_text"])
            else:
                return None

            key_root, _ = self._parse_der(decrypted_key)
            octets = self._all_octets(key_root)
            for candidate in reversed(octets):
                if len(candidate) in {16, 24, 32}:
                    return candidate
        except Exception as e:
            print(f"    [-] Firefox SDR key extraction failed: {e}")
        return None

    def _decrypt_firefox_login_field(self, encoded_value):
        if not encoded_value or not self.firefox_sdr_key:
            return "<ENCRYPTED_FIREFOX_LOGIN>"

        try:
            blob = base64.b64decode(encoded_value)
            root, _ = self._parse_der(blob)
            if len(root.get("children", [])) < 3:
                return "<FIREFOX_DECRYPTION_FAILED>"

            algorithm = root["children"][1]
            params = algorithm["children"][1] if len(algorithm.get("children", [])) > 1 else None
            iv = params.get("bytes", b"") if params else b""
            cipher_text = root["children"][2].get("bytes", b"")
            if len(iv) > 8 and iv[0] == 0x04:
                inner, _ = self._parse_der(iv)
                iv = inner.get("bytes", iv)
            if len(iv) > 8:
                iv = iv[-8:]

            key = DES3.adjust_key_parity(self.firefox_sdr_key[:24])
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            plain = self._pkcs7_unpad(cipher.decrypt(cipher_text))
            return plain.decode("utf-8", errors="ignore")
        except Exception:
            return "<FIREFOX_DECRYPTION_FAILED>"

    def _get_secret_key(self):
        """
        Extracts the DPAPI encrypted AES key from Chromium Local State.
        """
        if not self.local_state_path or not self.local_state_path.exists() or platform.system() != "Windows":
            return None

        try:
            with open(self.local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)

            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as e:
            print(f"    [-] Error extracting AES key from Local State: {e}")
            return None

    def _decrypt_gcm_password(self, encrypted_password, key):
        try:
            iv = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            auth_tag = encrypted_password[-16:]

            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt_and_verify(ciphertext, auth_tag)
            return decrypted_pass.decode("utf-8")
        except Exception:
            return "<DECRYPTION FAILED>"

    def _decrypt_dpapi_password(self, encrypted_password):
        try:
            decrypted_pass = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted_pass.decode("utf-8")
        except Exception:
            return "<DPAPI DECRYPTION FAILED>"

    def _parse_chromium(self):
        results = []
        browser_name = self._browser_label()

        if CRYPTO_AVAILABLE and platform.system() == "Windows":
            self.secret_key = self._get_secret_key()

        try:
            uri_path = self.db_path.absolute().as_posix()
            conn = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used
                FROM logins
                """
            )

            for row in cursor.fetchall():
                origin_url, action_url, username, encrypted_pass, date_created, date_last_used = row

                decrypted_password = "<ENCRYPTED>"
                if encrypted_pass:
                    if isinstance(encrypted_pass, bytes) and (
                        encrypted_pass.startswith(b"v10") or encrypted_pass.startswith(b"v11")
                    ):
                        if self.secret_key:
                            decrypted_password = self._decrypt_gcm_password(encrypted_pass, self.secret_key)
                        else:
                            decrypted_password = "<MISSING AES KEY: LOCAL STATE NOT FOUND>"
                    else:
                        if CRYPTO_AVAILABLE and platform.system() == "Windows":
                            decrypted_password = self._decrypt_dpapi_password(encrypted_pass)
                        else:
                            decrypted_password = "<DPAPI UNAVAILABLE>"
                else:
                    decrypted_password = ""

                results.append(
                    {
                        "Browser": browser_name,
                        "Artifact Type": "Login Credentials",
                        "Origin URL": origin_url,
                        "Action URL": action_url,
                        "Username": username,
                        "Password": decrypted_password,
                        "Password Status": "Decrypted"
                        if decrypted_password
                        and not decrypted_password.startswith("<")
                        else "Encrypted/Unavailable",
                        "Date Created": self._chrome_time(date_created),
                        "Date Last Used": self._chrome_time(date_last_used),
                    }
                )

            conn.close()
        except Exception as e:
            print(f"    [-] SQL Parse Error on {self.db_path.name}: {e}")

        return results

    def _parse_firefox(self):
        results = []
        browser_name = self._browser_label()

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                login_data = json.load(f)
        except Exception as e:
            print(f"    [-] JSON Parse Error on {self.db_path.name}: {e}")
            return results

        key_source = self.key_db_path.name if self.key_db_path and self.key_db_path.exists() else "Unavailable"
        self.firefox_sdr_key = self._extract_firefox_sdr_key()
        for login in login_data.get("logins", []):
            username = login.get("username", "")
            password = "<ENCRYPTED_FIREFOX_LOGIN>"
            status = f"Encrypted (requires NSS/key DB: {key_source})"

            if self.firefox_sdr_key:
                username = self._decrypt_firefox_login_field(login.get("encryptedUsername"))
                password = self._decrypt_firefox_login_field(login.get("encryptedPassword"))
                status = "Decrypted" if not str(password).startswith("<") else "Decryption Failed"

            results.append(
                {
                    "Browser": browser_name,
                    "Artifact Type": "Login Credentials",
                    "Origin URL": login.get("hostname", ""),
                    "Action URL": login.get("formSubmitURL") or login.get("httpRealm", ""),
                    "Username": username,
                    "Password": password,
                    "Password Status": status,
                    "Date Created": self._firefox_time_ms(login.get("timeCreated")),
                    "Date Last Used": self._firefox_time_ms(login.get("timeLastUsed")),
                    "Times Used": login.get("timesUsed", ""),
                }
            )

        return results

    def parse(self):
        """
        Extracts all saved logins and attempts to decrypt passwords when supported.
        """
        if not self.db_path.exists():
            return []

        if self.browser_type == "firefox":
            return self._parse_firefox()
        return self._parse_chromium()
