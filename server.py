import json
import os
from mcp.server.fastmcp import FastMCP

from rules import run_compliance_rules

# resolve the data file next to this script, so the server works no matter
# which directory the MCP host (client.py, Claude Code) launches it from
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloudsplaining_iam_details.json")
ENTITY_KEYS = {
    "user": ("UserDetailList", "UserName"),
    "role": ("RoleDetailList", "RoleName"),
    "group": ("GroupDetailList", "GroupName"),
    "policy": ("Policies", "PolicyName"),
}

#initialize the MCP Server
mcp = FastMCP("CloudComplianceAuditor")

#defining the tool that AI agent will use
@mcp.tool()
def fetch_cloud_policies() -> str:
    """
    Fetches the comprehensive AWS IAM account authorization details dump
    containing all inline and managed policies for compliance auditing.
    """
    file_path = DATA_FILE
    
    if not os.path.exists(file_path):
        # raise (not return) so MCP marks the result isError=True and the
        # client fails closed instead of treating an error message as data
        raise FileNotFoundError(f"Could not find {os.path.basename(file_path)} next to server.py.")
    
    with open(file_path, "r") as file:
        # loads the dense structural data; a parse error propagates as an MCP tool error
        data = json.load(file)
    # minimize layout spacing slightly to optimize LLM context usage
    return json.dumps(data, indent=2)

def _load():
    # returns parsed data; raises (-> MCP isError) rather than returning an error string
    return json.loads(fetch_cloud_policies())


@mcp.tool()
def list_iam_entities(kind: str = "all") -> str:
    """
    Lists IAM entity names in the dump with counts. kind is one of:
    all, user, role, group, policy. Use this before get_iam_entity.
    """
    kinds = list(ENTITY_KEYS) if kind == "all" else [kind]
    if any(k not in ENTITY_KEYS for k in kinds):
        raise ValueError(f"kind must be one of: all, {', '.join(ENTITY_KEYS)}")
    data = _load()
    out = {}
    for k in kinds:
        list_key, name_key = ENTITY_KEYS[k]
        names = [item.get(name_key) for item in data.get(list_key, [])]
        out[k] = {"count": len(names), "names": names}
    return json.dumps(out, indent=2)


@mcp.tool()
def get_iam_entity(name: str) -> str:
    """
    Returns the full JSON for one IAM user, role, group or managed policy by
    exact name, including attached/inline policies and policy documents.
    """
    data = _load()
    for kind, (list_key, name_key) in ENTITY_KEYS.items():
        for item in data.get(list_key, []):
            if item.get(name_key) == name:
                return json.dumps({"kind": kind, "entity": item}, indent=2)
    raise ValueError(f"No IAM user, role, group or policy named {name!r}. Use list_iam_entities to see names.")


@mcp.tool()
def run_rule_scan() -> str:
    """
    Runs the deterministic rule engine (rules.py) over the whole dump and
    returns its findings grouped by risk. Fails closed: raises on any error.
    """
    findings = run_compliance_rules(fetch_cloud_policies())
    by_risk = {}
    for f in findings:
        by_risk.setdefault(f["risk"], []).append(f["resource"])
    return json.dumps({"total_findings": len(findings), "by_risk": by_risk}, indent=2)


#run server using standard input/output
if __name__ == "__main__":
    mcp.run(transport='stdio')
