from parsers.browser_detection import browser_label, detect_browser


def test_detect_browser_uses_whole_tokens():
    assert detect_browser("safari_history.db") == "safari"
    assert detect_browser("tor_places.sqlite") == "tor"
    assert detect_browser("firefox_formhistory.sqlite") == "firefox"


def test_browser_label_ignores_tor_substrings_inside_other_words():
    assert browser_label("safari_history.db") == "Safari"
    assert browser_label("firefox_formhistory.sqlite") == "Firefox"
    assert browser_label("firefox_browser_storage") == "Firefox"
