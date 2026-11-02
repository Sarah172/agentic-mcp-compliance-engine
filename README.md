# MCP-Enabled Cloud Risk & Compliance Auditor

An agentic Python workflow that uses the **Model Context Protocol (MCP)** to ingest an AWS IAM configuration dump, scan it with deterministic security rules, and have an LLM explain each finding and propose a least-privilege fix.

The design principle: **rules decide, the LLM explains.** A deterministic Python rule engine decides what counts as a violation; the LLM never invents findings, it only explains and remediates the ones the rules confirmed.

## The problem

Auditing AWS IAM is dense, manual and error-prone. `aws iam get-account-authorization-details` produces huge JSON payloads that security teams have to sift through by hand. LLMs can help, but they need safe, structured access to that data, and their judgment shouldn't be the only thing deciding whether something is a risk.

## Architecture

```
┌──────────────┐  stdio / MCP  ┌──────────────┐
│  client.py   │ ────────────▶ │  server.py   │──▶ cloudsplaining_iam_details.json
│ (the agent)  │ ◀──────────── │ (MCP server) │
└──────┬───────┘               └──────────────┘
       │ raw IAM JSON
       ▼
┌──────────────┐   findings    ┌──────────────┐
│   rules.py   │ ────────────▶ │ gpt-4o-mini  │──▶ Compliance_Audit_Report_<time>.md
│ (rule engine)│               │ (explain +   │
└──────────────┘               │  remediate)  │
                               └──────────────┘
```

| Component | Role |
|---|---|
| **`server.py`** | MCP server (`FastMCP`). Exposes the IAM dump as tools. Errors are raised, so MCP marks them `isError` instead of passing error text along as data. |
| **`client.py`** | Spawns the server over stdio, fetches the data, then disconnects before the slow steps (the "handoff", which avoids timeouts on large payloads). Runs the rules, sends only the findings to the LLM, and writes a timestamped Markdown report. |
| **`rules.py`** | Deterministic rule engine. Scans every user, role, group and managed policy for `AdministratorAccess`, wildcard `*` actions, and `s3:*`. |
| **LLM** | OpenAI `gpt-4o-mini` with structured output (Pydantic). Explains why each finding is risky, assigns severity, and writes a corrected IAM policy snippet. |

## Fail-closed by design

A compliance tool must never mistake "I couldn't check" for "everything is fine."

An earlier version had exactly that bug: if the data file was missing, the error was swallowed, the rules returned an empty list, and the tool printed **"Infrastructure is secure"** with exit code 0. It now fails closed:

- `rules.py` raises `ComplianceScanError` on invalid JSON, an error message, an unrecognized format, or **zero resources scanned**. An empty findings list only ever means "scanned and clean."
- `server.py` raises on errors, so the client sees a real MCP error.
- `client.py` prints **SCAN FAILED** and exits with code **1**.

| Outcome | Message | Exit code |
|---|---|---|
| Scanned, no findings | ✅ Infrastructure is secure | 0 |
| Findings explained, report written | Success: report saved | 0 |
| Data missing, unreadable or unrecognized | ❌ SCAN FAILED | 1 |
| MCP or LLM error | ❌ error message | 1 |

The non-zero exit code means the tool can gate a CI pipeline safely.

## Quick start

You'll need Python 3.10+ and an OpenAI API key.

```bash
git clone https://github.com/Sarah172/agentic-mcp-compliance-engine.git
cd agentic-mcp-compliance-engine

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project folder (it's gitignored):

```
OPENAI_API_KEY=sk-...
```

Run the audit:

```bash
python client.py
```

The client starts the MCP server itself, so you never run `server.py` by hand. The report is saved as `Compliance_Audit_Report_<timestamp>.md`.

> `mcp` is pinned below 2.0: version 2 renamed `FastMCP`, and `server.py` won't start on it.

## Tests

```bash
pytest
```

30 tests, none of which call OpenAI or need an API key:

- **`tests/test_rules.py`**: every fail-closed path (error strings, malformed JSON, unknown formats, empty input), a genuinely clean policy, each detector, and the real sample dump.
- **`tests/test_server.py`**: the MCP tools, including that a missing data file raises instead of returning an error string.

17 of these tests fail against the original buggy rule engine, so they actively guard against the "error reported as secure" regression.

## Using it with Claude Code

The repo is set up so Claude Code can query the IAM data directly.

**MCP server.** `.mcp.json` registers `server.py` as the `compliance-auditor` server (created with `claude mcp add --scope project compliance-auditor -- python3 server.py`). Open the repo with `claude` and approve it once. Besides `fetch_cloud_policies`, it has smaller tools for interactive questions:

| Tool | What it does |
|---|---|
| `list_iam_entities` | Names and counts of users, roles, groups and policies |
| `get_iam_entity` | Full JSON for one entity by name |
| `run_rule_scan` | Runs the rule engine and groups findings by risk |

Example: *"How many roles are in the dump, and which ones does the rule scan flag for privilege escalation?"*

> On Windows, if `python3` isn't on your path, change `"command": "python3"` to `"python"` in `.mcp.json`.

**Skill.** `/iam-policy-review <name>` (in `.claude/skills/iam-policy-review/`) reviews one IAM entity against four risk categories: privilege escalation, data exfiltration, resource exposure, and infrastructure modification. It separates a role's trust policy from its permissions, and says whether the rule engine's result was a true positive, a false positive, right for the wrong reason, or missed.

**`CLAUDE.md`.** Project instructions for coding agents: commands, architecture, the fail-closed contract, and house rules (run tests before proposing changes, preserve CRLF line endings, never commit `.env`).

## Known limitations

The rule engine uses substring matching, so treat its output as a triage list, not a final verdict. Using the Claude Code integration above turned up:

- **False positives from trust policies.** `AdministratorAccess` is matched anywhere, including a role's trust policy. In the sample data, 40 of the 42 roles flagged for privilege escalation are flagged only because their trust policy names an SSO admin role as a principal.
- **Missed risks from attached policies.** Users and roles only list the *names* of their attached policies, so they aren't checked for what those policies grant. `privesc-sre-role` has `iam:*`, `ec2:*` and `s3:*` on all resources and isn't flagged.
- **Other gaps.** `Deny` statements are flagged like `Allow`; wildcards inside action lists, `NotAction`, and escalation paths like `iam:PassRole` + `ec2:RunInstances` aren't detected.

## Roadmap

- [ ] Parse policy statements properly instead of matching substrings: respect `Effect`, skip trust policies, and expand wildcards.
- [ ] Attribute attached managed policies to the users, roles and groups that hold them.
- [ ] Detect known privilege-escalation combinations (for example `iam:PassRole` + `ec2:RunInstances`).
- [ ] Read live data from AWS instead of a saved dump.

## Project structure

```
├── client.py                          # agent: MCP → rules → LLM → report
├── server.py                          # MCP server exposing the IAM data
├── rules.py                           # deterministic, fail-closed rule engine
├── cloudsplaining_iam_details.json    # sample IAM dump (Cloudsplaining test data)
├── dummy_policies.json                # older sample in a different format (not used)
├── tests/                             # pytest suite
├── CLAUDE.md                          # instructions for coding agents
├── .mcp.json                          # Claude Code MCP server config
└── .claude/skills/iam-policy-review/  # /iam-policy-review skill
```
