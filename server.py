import json
import os
from mcp.server.fastmcp import FastMCP

#initialize the MCP Server
mcp = FastMCP("CloudComplianceAuditor")

#defining the tool that AI agent will use
@mcp.tool()
def fetch_cloud_policies() -> str:
    """
    Fetches the comprehensive AWS IAM account authorization details dump
    containing all inline and managed policies for compliance auditing.
    """
    file_path = "cloudsplaining_iam_details.json"
    
    if not os.path.exists(file_path):
        # raise (not return) so MCP marks the result isError=True and the
        # client fails closed instead of treating an error message as data
        raise FileNotFoundError(f"Could not find {file_path} in the current directory.")
    
    with open(file_path, "r") as file:
        # loads the dense structural data; a parse error propagates as an MCP tool error
        data = json.load(file)
    # minimize layout spacing slightly to optimize LLM context usage
    return json.dumps(data, indent=2)

#run server using standard input/output
if __name__ == "__main__":
    mcp.run(transport='stdio')
