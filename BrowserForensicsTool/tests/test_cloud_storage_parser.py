from parsers.cloud_storage_parser import CloudStorageParser


def test_cloud_storage_parser_correlates_history_and_storage_records():
    parser = CloudStorageParser()

    results = parser.parse(
        history_records=[
            {
                "Browser": "Chrome",
                "URL": "https://drive.google.com/file/d/abc123/view",
                "Title": "Case file",
                "Last Visit Time": "2026-03-11T10:00:00Z",
                "Transition Type": "Link",
                "Visit Count": 2,
            }
        ],
        storage_records=[
            {
                "Browser": "Chrome",
                "Storage Category": "Local Storage",
                "Evidence Type": "Embedded URLs",
                "Origin / Scope": "https://onedrive.live.com",
                "Source File": "leveldb/000003.log",
                "Key": "recentEntry",
                "Value Preview": "download",
                "URL Candidates": "https://onedrive.live.com/?id=EVIDENCE123",
            }
        ],
    )

    providers = {record["Provider"] for record in results}
    sources = {record["Artifact Source"] for record in results}

    assert "Google Drive" in providers
    assert "Microsoft OneDrive" in providers
    assert "History" in sources
    assert "Browser Storage" in sources
