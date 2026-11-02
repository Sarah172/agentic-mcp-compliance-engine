import json


class ComplianceScanError(Exception):
    """Raised when the scan could not be completed (or scanned nothing).

    The rule engine fails closed: an empty findings list means "scanned and
    clean", never "something went wrong".
    """


def detect_admin_access(policy_str):
    return "AdministratorAccess" in policy_str

def detect_star_permissions(policy_str):
    return '"Action": "*"' in policy_str or '"Action": ["*"]' in policy_str

def detect_s3_full_access(policy_str):
    return "s3:*" in policy_str

def run_compliance_rules(raw_json_data):
    """
    Scans raw JSON payload against deterministic security rules and
    returns a list of programmatic findings.

    Raises ComplianceScanError if the input cannot be parsed, is not a
    recognized format, or yields zero resources to scan. An empty list is
    returned only when resources were scanned and none violated a rule.
    """
    if isinstance(raw_json_data, (bytes, bytearray)):
        try:
            raw_json_data = raw_json_data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ComplianceScanError(f"Input is not valid UTF-8: {e}") from e
    if not isinstance(raw_json_data, str):
        raise ComplianceScanError(
            f"Expected JSON text, got {type(raw_json_data).__name__}."
        )

    if raw_json_data.lstrip().startswith("Error"):
        raise ComplianceScanError(f"Data source reported an error: {raw_json_data.strip()}")

    try:
        data = json.loads(raw_json_data)
    except json.JSONDecodeError as e:
        raise ComplianceScanError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ComplianceScanError(
            f"Unrecognized format: expected a JSON object, got {type(data).__name__}."
        )

    resources_to_scan = []

    # parses Cloudsplaining AWS format
    cloudsplaining_keys = ["UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"]
    for key in cloudsplaining_keys:
        if key in data and isinstance(data[key], list):
            for item in data[key]:
                if not isinstance(item, dict):
                    raise ComplianceScanError(
                        f"Malformed entry in '{key}': expected an object, got {type(item).__name__}."
                    )
                # extracts actual name of AWS user, role, or policy
                name = item.get("UserName") or item.get("RoleName") or item.get("GroupName") or item.get("PolicyName") or "Unknown IAM Resource"

                # converts entire item block to string to run the string rules against it
                resources_to_scan.append({
                    "name": name,
                    "content_str": json.dumps(item)
                })

    if not resources_to_scan:
        raise ComplianceScanError(
            "No resources were scanned: unrecognized format or empty input "
            f"(expected a non-empty list under one of {cloudsplaining_keys})."
        )

    findings = []

    # runs deterministic rules against every extracted resource
    for resource in resources_to_scan:
        name = resource["name"]
        content = resource["content_str"]

        if detect_admin_access(content):
            findings.append({
                "resource": name,
                "risk": "Privilege Escalation",
                "trigger": "AdministratorAccess policy detected."
            })

        if detect_star_permissions(content):
            findings.append({
                "resource": name,
                "risk": "Infrastructure Modification",
                "trigger": "Wildcard '*' action detected."
            })

        if detect_s3_full_access(content):
            findings.append({
                "resource": name,
                "risk": "Data Exfiltration",
                "trigger": "s3:* full access detected."
            })

    return findings
