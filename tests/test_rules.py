import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from rules import (  # noqa: E402
    ComplianceScanError,
    detect_admin_access,
    detect_s3_full_access,
    detect_star_permissions,
    run_compliance_rules,
)


def payload(*policies, key="Policies"):
    return json.dumps({key: [{"PolicyName": f"p{i}", "Doc": p} for i, p in enumerate(policies)]})


CLEAN = {"Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}]}


# --- fail-closed cases ---
def test_error_string_raises():
    with pytest.raises(ComplianceScanError):
        run_compliance_rules("Error: Could not find cloudsplaining_iam_details.json")


def test_error_reading_string_raises():
    with pytest.raises(ComplianceScanError):
        run_compliance_rules("Error reading the Cloudsplaining policy file: boom")


@pytest.mark.parametrize("bad", ["{not json", "", "   ", "null-ish"])
def test_malformed_json_raises(bad):
    with pytest.raises(ComplianceScanError):
        run_compliance_rules(bad)


@pytest.mark.parametrize("raw", [
    json.dumps({"scanned_resources": [{"resource_id": "x"}]}),
    json.dumps({"foo": "bar"}),
    json.dumps([1, 2, 3]),
    json.dumps("just a string"),
    json.dumps(42),
])
def test_unrecognized_format_raises(raw):
    with pytest.raises(ComplianceScanError):
        run_compliance_rules(raw)


@pytest.mark.parametrize("raw", [
    "{}",
    "[]",
    json.dumps({"UserDetailList": [], "RoleDetailList": [], "GroupDetailList": [], "Policies": []}),
    json.dumps({"Policies": []}),
])
def test_empty_lists_raise(raw):
    with pytest.raises(ComplianceScanError):
        run_compliance_rules(raw)


def test_non_dict_entry_raises():
    with pytest.raises(ComplianceScanError):
        run_compliance_rules(json.dumps({"Policies": ["not-an-object"]}))


def test_non_string_input_raises():
    with pytest.raises(ComplianceScanError):
        run_compliance_rules(None)


# --- genuinely secure ---
def test_clean_policy_returns_empty_list():
    assert run_compliance_rules(payload(CLEAN)) == []


# --- detectors fire end to end ---
def test_admin_access_detected():
    f = run_compliance_rules(payload({"ManagedPolicies": [{"PolicyName": "AdministratorAccess"}]}))
    assert f == [{
        "resource": "p0",
        "risk": "Privilege Escalation",
        "trigger": "AdministratorAccess policy detected.",
    }]


def test_star_permissions_detected():
    f = run_compliance_rules(payload({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    assert [x["risk"] for x in f] == ["Infrastructure Modification"]


def test_s3_full_access_detected():
    f = run_compliance_rules(payload({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
    assert [x["risk"] for x in f] == ["Data Exfiltration"]


def test_detect_functions_directly():
    assert detect_admin_access("AdministratorAccess")
    assert detect_star_permissions('"Action": "*"')
    assert detect_star_permissions('"Action": ["*"]')
    assert detect_s3_full_access("s3:*")
    assert not detect_admin_access("x")
    assert not detect_star_permissions("x")
    assert not detect_s3_full_access("x")


def test_name_resolution_across_keys():
    raw = json.dumps({"RoleDetailList": [{"RoleName": "r", "x": "s3:*"}]})
    assert run_compliance_rules(raw)[0]["resource"] == "r"


# --- real data ---
def test_real_cloudsplaining_file_has_findings():
    with open(os.path.join(REPO, "cloudsplaining_iam_details.json")) as fh:
        raw = fh.read()
    findings = run_compliance_rules(raw)
    assert findings
    for f in findings:
        assert set(f) == {"resource", "risk", "trigger"}
