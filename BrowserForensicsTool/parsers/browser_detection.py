import re
from pathlib import Path


CHROMIUM_BROWSERS = frozenset({"chrome", "edge", "brave", "opera"})
MOZILLA_BROWSERS = frozenset({"firefox", "tor"})

_BROWSER_LABELS = {
    "chrome": "Chrome",
    "edge": "Edge",
    "brave": "Brave",
    "opera": "Opera",
    "tor": "Tor",
    "firefox": "Firefox",
    "safari": "Safari",
}


def _name_tokens(path_like):
    name = Path(path_like).name.lower()
    return {token for token in re.split(r"[^a-z0-9]+", name) if token}


def detect_browser(path_like):
    tokens = _name_tokens(path_like)
    if "torbrowser" in tokens:
        return "tor"

    for browser in ("chrome", "edge", "brave", "opera", "tor", "firefox", "safari"):
        if browser in tokens:
            return browser
    return "unknown"


def browser_label(path_like=None, browser=None):
    browser_key = browser or detect_browser(path_like or "")
    return _BROWSER_LABELS.get(browser_key, "Unknown")


def is_chromium(browser):
    return browser in CHROMIUM_BROWSERS


def is_firefox_family(browser):
    return browser in MOZILLA_BROWSERS
