
from utils.disk_imager import DiskImager


def test_disk_imager_discovers_profiles_from_mounted_root(tmp_path):
    chrome_profile = tmp_path / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    firefox_profile = tmp_path / "Users" / "alice" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release"
    safari_root = tmp_path / "Users" / "alice" / "Library" / "Safari"

    chrome_profile.mkdir(parents=True)
    firefox_profile.mkdir(parents=True)
    safari_root.mkdir(parents=True)

    (chrome_profile / "History").write_text("", encoding="utf-8")
    (chrome_profile / "Bookmarks").write_text("{}", encoding="utf-8")
    (firefox_profile / "places.sqlite").write_text("", encoding="utf-8")
    (safari_root / "History.db").write_text("", encoding="utf-8")

    imager = DiskImager()
    profiles = imager.discover_browser_profiles(tmp_path)

    assert chrome_profile in profiles["chrome"]
    assert firefox_profile in profiles["firefox"]
    assert safari_root in profiles["safari"]


def test_prepare_source_root_accepts_directory_without_materialization(tmp_path):
    mounted_root = tmp_path / "mounted_image"
    mounted_root.mkdir()

    imager = DiskImager()

    assert imager.prepare_source_root(mounted_root) == mounted_root
