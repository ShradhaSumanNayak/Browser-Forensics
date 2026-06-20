import fnmatch
import shutil
import tempfile
from pathlib import Path

try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import pyewf
except ImportError:
    pyewf = None


if pytsk3 and pyewf:
    class _EwfImgInfo(pytsk3.Img_Info):
        def __init__(self, filenames):
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(filenames)
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self):
            return self._ewf_handle.get_media_size()
else:
    _EwfImgInfo = None


class DiskImager:
    """
    Normalizes mounted directories and native forensic images into a local source root
    that the existing collectors can reuse without a separate parsing pipeline.
    """

    MATERIALIZE_PATTERNS = [
        "Users/*/AppData/Local/Google/Chrome/User Data",
        "Users/*/AppData/Local/Microsoft/Edge/User Data",
        "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data",
        "Users/*/AppData/Roaming/Opera Software",
        "Users/*/AppData/Roaming/Mozilla/Firefox",
        "Users/*/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser",
        "Users/*/OneDrive/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser",
        "Users/*/Library/Application Support/Google/Chrome",
        "Users/*/Library/Application Support/Microsoft Edge",
        "Users/*/Library/Application Support/BraveSoftware/Brave-Browser",
        "Users/*/Library/Application Support/com.operasoftware.Opera",
        "Users/*/Library/Application Support/Firefox",
        "Users/*/Library/Application Support/TorBrowser-Data/Browser",
        "Users/*/Library/Safari",
        "Users/*/Library/Cookies",
        "Users/*/Library/Containers/com.apple.Safari",
        "home/*/.config/google-chrome",
        "home/*/.config/microsoft-edge",
        "home/*/.config/BraveSoftware/Brave-Browser",
        "home/*/.config/opera",
        "home/*/.mozilla/firefox",
        "home/*/.tor-browser/Browser/TorBrowser/Data/Browser",
    ]

    DISCOVERY_PATTERNS = {
        "chrome": [
            "Users/*/AppData/Local/Google/Chrome/User Data/Default",
            "Users/*/AppData/Local/Google/Chrome/User Data/Profile *",
            "Users/*/Library/Application Support/Google/Chrome/Default",
            "Users/*/Library/Application Support/Google/Chrome/Profile *",
            "home/*/.config/google-chrome/Default",
            "home/*/.config/google-chrome/Profile *",
        ],
        "edge": [
            "Users/*/AppData/Local/Microsoft/Edge/User Data/Default",
            "Users/*/AppData/Local/Microsoft/Edge/User Data/Profile *",
            "Users/*/Library/Application Support/Microsoft Edge/Default",
            "Users/*/Library/Application Support/Microsoft Edge/Profile *",
            "home/*/.config/microsoft-edge/Default",
            "home/*/.config/microsoft-edge/Profile *",
        ],
        "brave": [
            "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default",
            "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/Profile *",
            "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default",
            "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Profile *",
            "home/*/.config/BraveSoftware/Brave-Browser/Default",
            "home/*/.config/BraveSoftware/Brave-Browser/Profile *",
        ],
        "opera": [
            "Users/*/AppData/Roaming/Opera Software/Opera Stable",
            "Users/*/AppData/Roaming/Opera Software/Opera GX Stable",
            "Users/*/Library/Application Support/com.operasoftware.Opera",
            "home/*/.config/opera",
        ],
        "firefox": [
            "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*",
            "Users/*/Library/Application Support/Firefox/Profiles/*",
            "home/*/.mozilla/firefox/*",
        ],
        "tor": [
            "Users/*/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/*default*",
            "Users/*/OneDrive/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/*default*",
            "Users/*/Library/Application Support/TorBrowser-Data/Browser/*default*",
            "home/*/.tor-browser/Browser/TorBrowser/Data/Browser/*default*",
        ],
        "safari": [
            "Users/*/Library/Safari",
        ],
    }

    def __init__(self, logger_callback=None, workspace_root=None):
        self.logger_callback = logger_callback
        default_workspace = Path(tempfile.gettempdir()) / "browser_forensics_images"
        self.workspace_root = Path(workspace_root) if workspace_root else default_workspace
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.last_metadata = {}
        self.last_materialized_root = None

    def _log(self, message):
        if self.logger_callback:
            self.logger_callback(message)
        else:
            print(message)

    def _safe_name(self, value):
        safe = "".join(char.lower() if char.isalnum() else "_" for char in str(value))
        while "__" in safe:
            safe = safe.replace("__", "_")
        return safe.strip("_") or "image"

    def ingest_raw_image(self, image_path):
        image = Path(image_path)
        metadata = {
            "path": str(image),
            "exists": image.exists(),
            "is_dir": image.is_dir(),
            "size_bytes": image.stat().st_size if image.exists() and image.is_file() else 0,
            "suffix": image.suffix.lower(),
            "native_image_support": bool(pytsk3),
            "ewf_support": bool(pyewf),
        }
        self.last_metadata = metadata

        if not metadata["exists"]:
            self._log(f"[-] Forensic image path not found: {image}")
            return metadata

        if metadata["is_dir"]:
            self._log(f"[*] Using mounted directory as image source root: {image}")
            return metadata

        self._log(
            f"[*] Image metadata: suffix={metadata['suffix'] or 'none'} size={metadata['size_bytes']} bytes "
            f"native_support={metadata['native_image_support']} ewf_support={metadata['ewf_support']}"
        )
        return metadata

    def prepare_source_root(self, image_path):
        image = Path(image_path)
        if not image.exists():
            self._log(f"[-] Cannot prepare source root. Path does not exist: {image}")
            return None

        if image.is_dir():
            return image

        if not pytsk3:
            self._log("[-] Native image parsing requires pytsk3. Falling back to mounted-directory mode only.")
            return None

        image_root = self.workspace_root / self._safe_name(image.stem)
        if image_root.exists():
            shutil.rmtree(image_root)
        image_root.mkdir(parents=True, exist_ok=True)

        copied = 0
        seen_targets = set()
        filesystems = self._open_filesystems(image)
        if not filesystems:
            self._log("[-] No readable filesystem was found inside the image.")
            return None

        try:
            for fs_entry in filesystems:
                fs = fs_entry["fs"]
                label = fs_entry["label"]
                self._log(f"[*] Scanning {label} for browser profile roots...")
                for pattern in self.MATERIALIZE_PATTERNS:
                    for match in self._expand_glob(fs, pattern):
                        dedupe_key = (label, match.lower())
                        if dedupe_key in seen_targets:
                            continue
                        seen_targets.add(dedupe_key)
                        if self._copy_entry(fs, match, image_root):
                            copied += 1
                            self._log(f"    [+] Materialized {match}")
        finally:
            self._close_filesystems(filesystems)

        if copied == 0:
            shutil.rmtree(image_root, ignore_errors=True)
            self._log("[-] No browser roots were materialized from the image.")
            return None

        self.last_materialized_root = image_root
        self._log(f"[+] Materialized {copied} browser root(s) to {image_root}")
        return image_root

    def discover_browser_profiles(self, source_root):
        root = Path(source_root)
        profiles = {browser: [] for browser in self.DISCOVERY_PATTERNS}
        if not root.exists():
            return profiles

        for browser, patterns in self.DISCOVERY_PATTERNS.items():
            seen = set()
            for pattern in patterns:
                for candidate in root.glob(pattern):
                    if not candidate.exists() or not candidate.is_dir():
                        continue
                    if not self._is_valid_profile(browser, candidate):
                        continue
                    normalized = str(candidate.resolve()) if candidate.exists() else str(candidate)
                    if normalized in seen:
                        continue
                    seen.add(normalized)
                    profiles[browser].append(candidate)

        return profiles

    def cleanup(self):
        if self.last_materialized_root and Path(self.last_materialized_root).exists():
            shutil.rmtree(self.last_materialized_root, ignore_errors=True)
            self.last_materialized_root = None

    def _is_valid_profile(self, browser, candidate):
        if browser in {"chrome", "edge", "brave", "opera"}:
            return any((candidate / name).exists() for name in ["History", "Bookmarks", "Login Data", "Web Data"])
        if browser == "firefox":
            return any((candidate / name).exists() for name in ["places.sqlite", "logins.json", "cookies.sqlite"])
        if browser == "tor":
            return any((candidate / name).exists() for name in ["places.sqlite", "logins.json", "cookies.sqlite"])
        if browser == "safari":
            return any((candidate / name).exists() for name in ["History.db", "Bookmarks.plist", "Downloads.plist"])
        return False

    def _open_filesystems(self, image_path):
        img_handle = self._open_image(image_path)
        if not img_handle:
            return []

        filesystems = []
        try:
            volume = pytsk3.Volume_Info(img_handle)
            for index, partition in enumerate(volume):
                description = partition.desc.decode("utf-8", errors="ignore").strip()
                if partition.len <= 0:
                    continue
                lowered = description.lower()
                if "unalloc" in lowered or "meta" in lowered:
                    continue
                try:
                    fs = pytsk3.FS_Info(img_handle, offset=partition.start * 512)
                    filesystems.append({"fs": fs, "img": img_handle, "label": f"partition_{index}:{description}"})
                except OSError:
                    continue
        except OSError:
            try:
                fs = pytsk3.FS_Info(img_handle)
                filesystems.append({"fs": fs, "img": img_handle, "label": "filesystem_0"})
            except OSError:
                pass

        if not filesystems:
            try:
                img_handle.close()
            except Exception:
                pass
        return filesystems

    def _close_filesystems(self, filesystems):
        closed = set()
        for entry in filesystems:
            img = entry.get("img")
            if not img or id(img) in closed:
                continue
            closed.add(id(img))
            try:
                img.close()
            except Exception:
                pass

    def _open_image(self, image_path):
        suffix = image_path.suffix.lower()
        if suffix == ".e01":
            if not pyewf or not _EwfImgInfo:
                self._log("[-] E01 support requires pyewf in addition to pytsk3.")
                return None
            filenames = pyewf.glob(str(image_path)) if hasattr(pyewf, "glob") else [str(image_path)]
            return _EwfImgInfo(filenames)
        return pytsk3.Img_Info(str(image_path))

    def _expand_glob(self, fs, pattern):
        segments = [segment for segment in pattern.strip("/").split("/") if segment]
        matches = []

        def walk(current_path, index):
            try:
                directory = fs.open_dir(path=current_path)
            except OSError:
                return

            segment = segments[index]
            for entry in directory:
                name = self._entry_name(entry)
                if not name or name in {".", ".."}:
                    continue
                if not fnmatch.fnmatch(name.lower(), segment.lower()):
                    continue

                next_path = f"{current_path.rstrip('/')}/{name}" if current_path != "/" else f"/{name}"
                if index == len(segments) - 1:
                    matches.append(next_path)
                    continue

                if self._entry_is_dir(entry):
                    walk(next_path, index + 1)

        if segments:
            walk("/", 0)
        return matches

    def _entry_name(self, entry):
        try:
            name = entry.info.name.name
        except AttributeError:
            return ""
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="ignore")
        return str(name)

    def _entry_is_dir(self, entry):
        try:
            return entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        except AttributeError:
            return False

    def _copy_entry(self, fs, image_path, destination_root):
        try:
            directory = fs.open_dir(path=image_path)
            is_dir = True
        except OSError:
            directory = None
            is_dir = False

        target = destination_root / image_path.lstrip("/").replace(":", "_")
        if is_dir:
            target.mkdir(parents=True, exist_ok=True)
            for entry in directory:
                name = self._entry_name(entry)
                if not name or name in {".", ".."}:
                    continue
                child_path = f"{image_path.rstrip('/')}/{name}" if image_path != "/" else f"/{name}"
                self._copy_entry(fs, child_path, destination_root)
            return True

        try:
            source_file = fs.open(image_path)
            size = int(getattr(source_file.info.meta, "size", 0) or 0)
        except OSError:
            return False

        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(target, "wb") as handle:
                offset = 0
                chunk_size = 1024 * 1024
                while offset < size:
                    chunk = source_file.read_random(offset, min(chunk_size, size - offset))
                    if not chunk:
                        break
                    handle.write(chunk)
                    offset += len(chunk)
                if size == 0:
                    handle.write(b"")
            return True
        except OSError:
            return False
