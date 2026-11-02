---
name: iam-policy-review
description: Review one IAM user, role, group or managed policy from the Cloudsplaining dump for privilege escalation, data exfiltration, resource exposure and infrastructure modification risk. Use when asked to review, audit or explain the risk of a named IAM entity, or to check whether a rule-engine finding is real.
argument-hint: <iam-entity-name>
allowed-tools: mcp__compliance-auditor__get_iam_entity, mcp__compliance-auditor__list_iam_entities, mcp__compliance-auditor__run_rule_scan
---

# IAM policy review

Review the IAM entity named in `$ARGUMENTS` using the `compliance-auditor` MCP server. Never read `cloudsplaining_iam_details.json` directly and never call `fetch_cloud_policies` (the full dump is ~800KB).

## Steps

1. **Load the entity.** Call `get_iam_entity` with the exact name. If it is not found, call `list_iam_entities` and suggest the closest names, then stop.
2. **Collect effective permissions.** For a user, role or group, list its inline policies and attached managed policies. For each attached managed policy, call `get_iam_entity` on the policy name and use only the version where `IsDefaultVersion` is true. For a group member, note that group policies also apply.
3. **Separate trust from permissions.** For a role, review `AssumeRolePolicyDocument` separately: it says *who can assume* the role, not *what it can do*. Never count a principal name (for example `AWSReservedSSO_AdministratorAccess_…`) as a permission.
4. **Check each Allow statement** (Deny statements reduce risk; note them, never flag them) against the four categories:
   - **Privilege Escalation:** `*` actions, `iam:*`, `iam:PassRole` on `*` combined with a compute launch (`ec2:RunInstances`, `lambda:CreateFunction`, `cloudformation:CreateStack`, `glue:CreateDevEndpoint`), `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`/`PutUserPolicy`/`PutRolePolicy`, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` on `*`.
   - **Data Exfiltration:** `s3:GetObject`, `s3:*`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt` on broad resources.
   - **Resource Exposure:** actions that change resource policies or sharing, such as `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `kms:PutKeyPolicy`, `lambda:AddPermission`, `ecr:SetRepositoryPolicy`.
   - **Infrastructure Modification:** write, create or delete actions on `Resource: "*"` without conditions.
   Also check `NotAction`, wildcards inside action lists, and whether a `Condition` actually narrows the grant.
5. **Compare with the rule engine.** Call `run_rule_scan` and see whether the entity is listed. Classify the rule engine's result as one of: true positive, true positive for the wrong reason, false positive, or missed (false negative). Explain which text the substring rule most likely matched.

## Output format

```
## IAM review: <name> (<kind>)
Verdict: <Critical | High | Medium | Low | No material risk>

| Category | Finding | Evidence (policy → statement) |
|---|---|---|

Rule engine: <flagged as X / not flagged> → <true positive | right result, wrong reason | false positive | missed>
Why: <one or two sentences>

Least-privilege fix:
<corrected policy JSON for the riskiest statement only>
```

Quote statements exactly from the tool output. If you cannot see a policy document, say so and do not guess. A review that could not load the data is a failed review, never "No material risk".
