import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import server  # noqa: E402


def test_fetch_raises_when_data_file_missing(monkeypatch, tmp_path):
    # must raise (so MCP sets isError), never return an "Error: ..." string
    monkeypatch.setattr(server, "DATA_FILE", str(tmp_path / "missing.json"))
    with pytest.raises(FileNotFoundError):
        server.fetch_cloud_policies()


def test_fetch_works_from_another_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert "UserDetailList" in json.loads(server.fetch_cloud_policies())


def test_list_iam_entities_counts():
    out = json.loads(server.list_iam_entities("all"))
    assert set(out) == {"user", "role", "group", "policy"}
    assert out["role"]["count"] == len(out["role"]["names"]) > 0


def test_list_iam_entities_rejects_bad_kind():
    with pytest.raises(ValueError):
        server.list_iam_entities("bucket")


def test_get_iam_entity_found_and_missing():
    name = json.loads(server.list_iam_entities("user"))["user"]["names"][0]
    assert json.loads(server.get_iam_entity(name))["kind"] == "user"
    with pytest.raises(ValueError):
        server.get_iam_entity("definitely-not-a-real-entity")


def test_run_rule_scan_matches_rules_engine():
    out = json.loads(server.run_rule_scan())
    assert out["total_findings"] == sum(len(v) for v in out["by_risk"].values()) > 0
