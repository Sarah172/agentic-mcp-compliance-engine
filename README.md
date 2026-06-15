# MCP-Enabled Cloud Risk & Compliance Auditor

An Agentic AI workflow built in Python that utilizes the Model Context Protocol (MCP) to autonomously ingest, analyze, and triage massive AWS IAM infrastructure configurations for enterprise security compliance.

## The Problem

In enterprise cloud environments, auditing Identity and Access Management (IAM) policies is a dense, manual, and error-prone process. Standard CLI outputs (like `aws iam get-account-authorization-details`) generate massive JSON payloads that security teams must sift through to find subtle misconfigurations. 

Standard LLMs struggle with this because they lack secure, direct access to local infrastructure dumps or live cloud environments. This project solves that data-ingestion bottleneck by using an **Agentic Workflow** powered by MCP to securely feed complex IAM data to an LLM for automated triage and remediation.

## Architecture

This project is built using a decoupled Client-Server architecture:

* **The Brain (LLM):** OpenAI `gpt-4o-mini` is used as the reasoning engine, prompted with a strict system instruction based on the industry-standard **Cloudsplaining** risk framework.
* **The Senses (MCP Server):** A local server built with the `mcp.server.fastmcp` Python SDK. It acts as a secure tool-provider, allowing the AI agent to reach into the local file system and extract complex JSON datasets without exposing the broader OS.
* **The Hands (Python Client):** An asynchronous Python script that manages the session, requests the data via MCP, orchestrates the LLM API call, and generates a timestamped `.md` compliance artifact.

## How it Works

1. **Initialization:** The Client script spawns the local MCP Server using standard input/output (`stdio`).
2. **Data Ingestion:** The Client requests the `fetch_cloud_policies` tool. The Server securely reads a dense AWS IAM JSON dump (mimicking Cloudsplaining outputs) and returns the data payload.
3. **The "Handoff":** To prevent timeout crashes on massive datasets, the Client immediately disconnects from the MCP server once the data is secured in memory.
4. **AI Triage:** The Client forwards the payload to the LLM. The AI analyzes the data for four core risks: *Privilege Escalation, Data Exfiltration, Resource Exposure, and Infrastructure Modification*.
5. **Artifact Generation:** The Agent dynamically writes the corrected IAM JSON snippets and saves an official, timestamped Markdown report to the local directory.

## Demo / How to Run

To run this prototype locally, you will need an OpenAI API key.

**1. Install Dependencies**
```bash
pip install -r requirements.txt