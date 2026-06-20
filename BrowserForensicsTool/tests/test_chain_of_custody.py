import json

from utils.chain_of_custody import ChainOfCustody, SIGNING_AVAILABLE, log_custody_event


def test_chain_of_custody_log_is_verifiable(tmp_path, monkeypatch):
    monkeypatch.setenv("BFT_CUSTODY_KEY_DIR", str(tmp_path / "keys"))
    log_file = tmp_path / "chain.jsonl"

    log_custody_event(log_file, "Evidence Collected", "Collected browser profile", investigator="Analyst")

    signer = ChainOfCustody()
    assert signer.verify_log_file(log_file)

    exported_key = log_file.parent / "chain_of_custody_public.pem"
    if SIGNING_AVAILABLE:
        assert exported_key.exists()

    line = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert line["signature"]
    assert line["payload"]["data"]["event"] == "Evidence Collected"
