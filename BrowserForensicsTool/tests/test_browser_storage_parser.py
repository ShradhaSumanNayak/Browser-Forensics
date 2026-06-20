from pathlib import Path

from parsers.browser_storage_parser import BrowserStorageParser


def test_browser_storage_parser_extracts_embedded_urls_from_fixture():
    fixture_dir = Path(__file__).parent / "fixtures" / "browser_storage" / "chrome_local_storage_leveldb"
    parser = BrowserStorageParser(fixture_dir)

    results = parser.parse()

    assert results
    assert any(record["Browser"] == "Chrome" for record in results)
    assert any("drive.google.com" in record.get("URL Candidates", "") for record in results)
