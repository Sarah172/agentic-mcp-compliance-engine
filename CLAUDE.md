# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pip install -r requirements.txt     # openai, mcp>=1.2,<2, python-dotenv, pydantic, pytest
python client.py                    # run the full audit (needs OPENAI_API_KEY in env or .env)
pytest                              # run all tests
pytest tests/test_rules.py::test_error_string_raises   # single test
```

There is no build or lint config. `client.py` spawns `server.py` itself over stdio (using `sys.executable`), so the server is never started manually. `server.py` finds `cloudsplaining_iam_details.json` next to itself, so it works from any directory; generated reports land in the current directory.

## Architecture

A neuro-symbolic pipeline: MCP fetches the data, deterministic Python rules decide what is a violation, and the LLM only explains and remediates what the rules flagged.

1. **`server.py`**: FastMCP server. `fetch_cloud_policies` (used by `client.py`) returns the contents of `cloudsplaining_iam_details.json` (about 800KB, in `aws iam get-account-authorization-details` / Cloudsplaining format). It raises on a missing file or a parse error so MCP sets `isError=True`. `list_iam_entities`, `get_iam_entity` and `run_rule_scan` are smaller query tools for interactive use from Claude Code.
2. **`client.py`** (`run_agent`): connects to the server, calls the tool, then closes the MCP session before doing anything else. The "handoff" avoids timeouts on the large payload. It then runs `rules.run_compliance_rules`. Only the small findings list is sent to `gpt-4o-mini`, using structured output (`AuditReport` / `FindingDetail` Pydantic models). It writes `Compliance_Audit_Report_<timestamp>.md`, which is gitignored (`Compliance_Audit_Report_*.md`).
3. **`rules.py`**: the rule engine. It scans each item under `UserDetailList`, `RoleDetailList`, `GroupDetailList` and `Policies`. The rules are substring checks on the JSON-serialized item: `AdministratorAccess`, `"Action": "*"`, and `s3:*`.

## Fail-closed contract (important)

An empty findings list from `run_compliance_rules` means "scanned and clean". Anything else, such as an MCP error, an `Error...` string, invalid JSON, an unrecognized format, or zero resources scanned, must raise `ComplianceScanError`. `client.run_agent` turns that into exit code 1 with a "SCAN FAILED" message. Keep this behavior when changing either file, and never return `[]` on error. `tests/test_rules.py` covers these cases.

## Other files

`dummy_policies.json` uses a different schema (`scanned_resources`). The rule engine does not recognize it, so it would raise "No resources were scanned". It is not wired into the pipeline.

## Known limitations of the rule engine (human-added)

The detectors are substring matches on `json.dumps(item)`, so treat their output as a triage list, not a verdict:

- **Trust policies are scanned like permissions.** `detect_admin_access` matches `AdministratorAccess` anywhere, including a role's `AssumeRolePolicyDocument`. In the sample data, 40 of the 42 roles flagged for Privilege Escalation are flagged only because their trust policy names the `AWSReservedSSO_AdministratorAccess_…` role as a principal. Some (like `fn1-privesc3-partial-role`, which has `iam:PassRole` on `*` plus `ec2:RunInstances`) are real risks the rules flagged for the wrong reason; others are false positives.
- **Effect is ignored.** A `"Effect": "Deny"` statement with `"Action": "*"` is flagged as a violation (the sample data has 3 Deny statements in default policy versions).
- **Wildcards inside lists are missed.** `"Action": ["s3:GetObject", "*"]` does not match `'"Action": ["*"]'`.
- **`NotAction`, `iam:PassRole` on `*`, and other escalation paths are not checked.** The LLM step cannot add findings the rules missed; it only explains what they flagged.
- **Attached policies aren't attributed to who holds them.** A user, role or group item only contains the *names* of its attached managed policies, so the entity itself is never checked for what those policies grant. `privesc-sre-role` (attached `iam:*`, `ec2:*`, `s3:*` on `*`) is not flagged at all; its policy is flagged only for Data Exfiltration because no rule matches `iam:*`. Found with `/iam-policy-review privesc-sre-role`.
- **One IAM entity is one resource.** Every non-default policy version is scanned too, so old versions can produce findings.

When fixing any of these, add a failing test first, and keep the fail-closed contract.

## Rules for agents working in this repo (human-added)

- **Run `pytest` and show it passing before proposing a change.** Tests must not call OpenAI or need `OPENAI_API_KEY`; test `rules.py` directly and keep `client.py` logic thin.
- **Preserve line endings.** `rules.py`, `server.py`, `client.py` and `requirements.txt` use CRLF. Converting them turns a small fix into a whole-file diff that cannot be reviewed.
- **Keep `mcp` pinned below 2.** MCP SDK 2.x renamed `FastMCP` and `server.py` will not start.
- **Never commit `.env`** or paste API keys into files, prompts or reports.
- **Do not weaken a check to make a test pass.** If a detector produces a false positive, document it here or fix the detector; do not delete the test.

## MCP and skills

- The repo ships `.mcp.json`, which registers `server.py` as the `compliance-auditor` MCP server for Claude Code. Its `fetch_cloud_policies` tool returns the full IAM dump (~800KB); prefer the summary tools when you only need counts or one entity.
- `/iam-policy-review` (in `.claude/skills/iam-policy-review/`) reviews one IAM entity or policy against the four Cloudsplaining risk categories.
