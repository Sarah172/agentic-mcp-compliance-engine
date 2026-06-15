import json

def detect_admin_access(policy_str):
    return "AdministratorAccess" in policy_str

def detect_star_permissions(policy_str):
    return '"Action": "*"' in policy_str or '"Action": ["*"]' in policy_str

def detect_s3_full_access(policy_str):
    return "s3:*" in policy_str

def run_compliance_rules(raw_json_data):
    """
    Scans the raw JSON payload against deterministic security rules.
    Returns a list of programmatic findings.
    """
    findings = []
    
    try:
        data = json.loads(raw_json_data)
        resources_to_scan = []
        
        # Parse Cloudsplaining AWS Format
        cloudsplaining_keys = ["UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"]
        for key in cloudsplaining_keys:
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    # Extract the actual name of the AWS user, role, or policy
                    name = item.get("UserName") or item.get("RoleName") or item.get("GroupName") or item.get("PolicyName") or "Unknown IAM Resource"
                    
                    # Convert the entire item block to a string to run our regex/string rules against it
                    resources_to_scan.append({
                        "name": name,
                        "content_str": json.dumps(item)
                    })

        # Run the deterministic rules against every extracted resource
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
                
    except Exception as e:
        print(f"Rule Engine Error: {e}")
        
    return findings