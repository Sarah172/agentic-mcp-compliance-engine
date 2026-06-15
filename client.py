import asyncio
import os
import sys
import json
from datetime import datetime
from typing import List
from pydantic import BaseModel
from openai import AsyncOpenAI
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from dotenv import load_dotenv

# NEW: Import your deterministic rule engine
from rules import run_compliance_rules

# --- Pydantic Data Models ---
class FindingDetail(BaseModel):
    severity: str
    category: str
    resource: str
    explanation: str
    remediation: str

class AuditReport(BaseModel):
    findings: List[FindingDetail]

# --- Initialization ---
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("❌ [ERROR] OPENAI_API_KEY not found.")

llm_client = AsyncOpenAI()

async def run_agent():
    print("Agent: Starting up...")
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    server_params = StdioServerParameters(command=sys.executable, args=["server.py"], env=env)
    raw_data = ""

    # --- STEP 1: RETRIEVE DATA VIA MCP ---
    try:
        print("Agent: Spawning the MCP Server...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("Agent: Requesting cloud policies from MCP server...")
                result = await session.call_tool("fetch_cloud_policies", arguments={})
                raw_data = result.content[0].text
                print("Agent: Data retrieved! Safely closing MCP connection...\n")
    except Exception as e:
        print(f"\n❌ [MCP ERROR] Failed to get data: {e}")
        return

    # --- STEP 2: DETERMINISTIC RULE SCAN (Neuro-Symbolic Pipeline) ---
    print("Agent: Running deterministic Python rule engine...")
    hardcoded_findings = run_compliance_rules(raw_data)
    
    if not hardcoded_findings:
        print("✅ Rule engine found zero vulnerabilities. Infrastructure is secure.")
        return
        
    print(f"Agent: Rule engine flagged {len(hardcoded_findings)} resources. Forwarding to LLM for context mapping...\n")

    # --- STEP 3: LLM EXPLANATION & REMEDIATION ---
    try:
        system_prompt = """
        You are an elite Cloud Security Engineer. You are receiving a list of CONFIRMED security vulnerabilities flagged by a deterministic rule engine.
        
        For each finding provided:
        1. Explain exactly WHY this specific configuration is a dangerous security risk.
        2. Provide the exact corrected IAM Policy JSON snippet to remediate the issue based on the principle of least privilege.
        3. Assign a severity (High, Critical).
        """
        
        # We only send the findings, NOT the massive raw JSON!
        findings_payload = json.dumps(hardcoded_findings, indent=2)
        
        response = await llm_client.beta.chat.completions.parse(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Explain and remediate these confirmed findings:\n{findings_payload}"}
            ],
            response_format=AuditReport
        )
        
        report_data = response.choices[0].message.parsed
        
        # --- STEP 4: DYNAMIC MARKDOWN GENERATION ---
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Compliance_Audit_Report_{timestamp}.md"
        
        with open(filename, "w", encoding="utf-8") as file:
            file.write("# Hybrid AI Security Audit (Rule-Based + LLM)\n")
            file.write(f"**Generated on:** {datetime.now().strftime('%B %d, %Y at %I:%M %p')}\n\n")
            file.write("---\n\n")
            file.write(f"### Executive Summary\n")
            file.write(f"The deterministic rule engine identified **{len(report_data.findings)}** programmatic violations. LLM-generated remediation strategies are detailed below.\n\n")
            file.write("---\n\n")
            
            for idx, finding in enumerate(report_data.findings, 1):
                file.write(f"## {idx}. [{finding.severity}] {finding.category}\n")
                file.write(f"**Resource:** `{finding.resource}`\n\n")
                file.write(f"**Contextual Risk Analysis:**\n{finding.explanation}\n\n")
                file.write(f"**Remediation Code:**\n```json\n{finding.remediation}\n```\n")
                file.write("---\n\n")
                    
        print(f"Success: Official audit artifact saved locally as '{filename}'")

    except Exception as e:
        print(f"\n [LLM ERROR] The AI processing failed: {e}")

if __name__ == "__main__":
    asyncio.run(run_agent())