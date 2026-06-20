from main import execute_extraction


def test_execute_extraction_rejects_root_output_path(tmp_path):
    logs = []

    assert execute_extraction(output=tmp_path.anchor, do_chrome=True, logger_callback=logs.append) is False
    assert any("Invalid or unsafe output directory" in message for message in logs)


def test_execute_extraction_rejects_invalid_image_path(tmp_path):
    logs = []

    assert execute_extraction(
        output=str(tmp_path / "case_output"),
        do_chrome=True,
        image_path="\x00",
        logger_callback=logs.append,
    ) is False
    assert any("Invalid or unsafe image path" in message for message in logs)
