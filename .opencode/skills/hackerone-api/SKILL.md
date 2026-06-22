---
name: hackerone-api
description: Query the HackerOne GraphQL API for program scope, weakness type exclusions, disclosed reports by target, or disclosed reports by vulnerability class. Requires HACKERONE_API_TOKEN. Used by caido-intel for centralized intel gathering before probing.
---

# HackerOne API Skill

Use this skill whenever you need to query the HackerOne GraphQL API — for program scope, weakness type exclusions, disclosed reports by target, or disclosed reports by vulnerability class.

---

## Authentication

H1 uses HTTP Basic Auth over the GraphQL endpoint. The token is stored as an environment variable:

```bash
echo $HACKERONE_API_TOKEN
```

Expected format: `username:api-token` (e.g. `d0b0:abc123...`). If empty, print:
```
[hackerone-api] WARN: HACKERONE_API_TOKEN not set.
  Export it: export HACKERONE_API_TOKEN="username:api-token"
  Skipping H1 API queries — falling back to manual scope input.
```
And return empty results. Do NOT abort the parent workflow.

The GraphQL endpoint:
```
https://api.hackerone.com/v1/graphql
```

Base curl pattern — reuse for every query:
```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{"query": "<QUERY>", "variables": <VARIABLES_JSON>}'
```

---

## Rate Limits

H1 enforces per-minute and per-hour limits. Safe defaults:
- Max 10 requests per minute
- Sleep 2s between consecutive queries
- On HTTP 429: sleep 60s and retry once
- On repeated 429: skip remaining queries, return what was collected so far

```bash
sleep 2  # between every query
```

---

## Query 1 — Find Program by Handle

Use when you know the target name and want to verify it exists on H1 and get its handle.

```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{
    "query": "query ProgramLookup($handle: String!) { team(handle: $handle) { id handle name policy submission_state offers_bounties } }",
    "variables": {"handle": "<target_handle>"}
  }'
```

Parse: `data.team` — if null, program not found on H1. If found, extract `id`, `handle`, `name`, `offers_bounties`.

Target handle is the lowercase program name with hyphens (e.g. `myfitnesspal`, `soundcloud`). Try common variations if first attempt returns null: lowercase, hyphenated, with/without dashes.

---

## Query 2 — Program Scope (In-scope and Out-of-scope assets)

```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{
    "query": "query ProgramScope($handle: String!) { team(handle: $handle) { structured_scope_versions(archived: false) { edges { node { asset_type asset_identifier instruction eligible_for_bounty eligible_for_submission } } } } }",
    "variables": {"handle": "<target_handle>"}
  }'
```

Parse: `data.team.structured_scope_versions.edges[].node`

Extract two lists:
- `in_scope`: nodes where `eligible_for_submission: true`
- `out_of_scope`: nodes where `eligible_for_submission: false`

Store as `program_scope.assets_in_scope` and `program_scope.assets_out_of_scope` in findings.json.

---

## Query 3 — Weakness/Vuln Class Exclusions from Policy

H1 does not expose vuln class exclusions as structured data in the GraphQL API. Parse them from the `policy` field returned in Query 1.

```bash
python3 << 'PYEOF'
import json, re

policy_text = """<POLICY_TEXT>"""

# Common out-of-scope vuln class patterns
OOS_PATTERNS = [
    r"(self[\-\s]?xss)",
    r"(csrf\b.*?(?:low|no impact|not.*?scope|out of scope))",
    r"(rate limit)",
    r"(denial[\-\s]of[\-\s]service|dos\b)",
    r"(clickjack)",
    r"(missing\s+(?:security\s+)?headers?)",
    r"(ssl\b|tls\b|https?\s+(?:downgrade|mismatch))",
    r"(email\s+(?:spoof|verif))",
    r"(username\s+enumeration)",
    r"(open\s+redirect.*?(?:low|not.*?scope|out of scope))",
    r"(social\s+engineering)",
    r"(physical\s+(?:access|attack))",
    r"(account\s+lockout)",
    r"(brute\s+force)",
]

found_oos = []
policy_lower = policy_text.lower()
for pattern in OOS_PATTERNS:
    if re.search(pattern, policy_lower):
        found_oos.append(re.search(pattern, policy_lower).group(1))

print(json.dumps({"out_of_scope_vuln_classes": found_oos}))
PYEOF
```

Store result in `program_scope.out_of_scope_vuln_classes`. Always combine with any user-provided `Out of scope vuln classes:` input — user input takes priority.

---

## Query 4 — Disclosed Reports for Target (Target-Specific Pass)

```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{
    "query": "query DisclosedReports($handle: String!, $count: Int!) { team(handle: $handle) { disclosed_reports(first: $count) { edges { node { id title severity { rating } weakness { name external_id } disclosed_at } } } } }",
    "variables": {"handle": "<target_handle>", "count": 20}
  }'
```

Parse: `data.team.disclosed_reports.edges[].node`

Extract per report:
- `id` → H1 report URL: `https://hackerone.com/reports/<id>`
- `title`
- `severity.rating` (none/low/medium/high/critical)
- `weakness.name` and `weakness.external_id` (CWE)
- `disclosed_at`

Store as `h1_intel.target_reports` array in findings.json. Key the entire h1_intel block with `fetched_at` timestamp for TTL checking.

---

## Query 5 — Disclosed Reports by Weakness Type (Weakness-Type Pass)

Run once per unique vulnerability category present in `findings.json` attack chains that did not already appear in the target-specific pass.

Map chain categories to H1 weakness names:
```
idor      → "Insecure Direct Object Reference (IDOR)"
auth      → "Improper Authentication"
csrf      → "Cross-Site Request Forgery (CSRF)"
graphql   → "GraphQL"
mass      → "Mass Assignment"
jwt       → "Improper Authentication"
admin     → "Improper Access Control"
```

```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{
    "query": "query WeaknessReports($type: String!, $count: Int!) { disclosed_vulnerabilities(weakness_id: $type, first: $count, order_by: { field: SEVERITY, direction: DESC }) { edges { node { id title team { handle } severity { rating } weakness { name } disclosed_at } } } }",
    "variables": {"type": "<weakness_name>", "count": 15}
  }'
```

Parse and store under `h1_intel.weakness_reports[<category>]` array.

Note: if the `disclosed_vulnerabilities` root query is unavailable on your API tier, fall back to searching via `hacktivity` query:
```bash
curl -s -u "$HACKERONE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://api.hackerone.com/v1/graphql \
  -d '{
    "query": "query Hacktivity($count: Int!) { hacktivity_items(first: $count, order_by: { field: POPULAR, direction: DESC }, where: { report: { disclosed: { _eq: true } } }) { edges { node { ... on HacktivityItem { report { id title severity { rating } weakness { name } team { handle } } } } } } }",
    "variables": {"count": 25}
  }'
```

---

## Error Handling

Always wrap queries in error checks:

```bash
python3 << 'PYEOF'
import json, sys

raw = """<CURL_OUTPUT>"""

try:
    data = json.loads(raw)
except json.JSONDecodeError:
    print("[hackerone-api] ERROR: Invalid JSON response")
    sys.exit(0)  # non-fatal — parent continues

if "errors" in data:
    for e in data["errors"]:
        print(f"[hackerone-api] GraphQL error: {e.get('message','unknown')}")
    sys.exit(0)

if not data.get("data"):
    print("[hackerone-api] WARN: Empty data in response")
    sys.exit(0)

# Safe to parse data here
print(json.dumps(data["data"], indent=2))
PYEOF
```

All errors are non-fatal. Always print a `[hackerone-api]` prefixed message and allow the parent agent to continue.

---

## findings.json Write Pattern

Always merge — never overwrite. Use this pattern:

```bash
python3 << 'PYEOF'
import json, datetime, os

findings_path = "<output_dir>/findings.json"
d = json.load(open(findings_path))

if "h1_intel" not in d:
    d["h1_intel"] = {}

d["h1_intel"]["fetched_at"] = datetime.datetime.utcnow().isoformat() + "Z"
d["h1_intel"]["target_reports"] = <TARGET_REPORTS_LIST>
d["h1_intel"]["weakness_reports"] = <WEAKNESS_REPORTS_DICT>

if "program_scope" not in d:
    d["program_scope"] = {}

d["program_scope"]["platform"] = "hackerone"
d["program_scope"]["handle"] = "<handle>"
d["program_scope"]["assets_in_scope"] = <IN_SCOPE_LIST>
d["program_scope"]["assets_out_of_scope"] = <OUT_OF_SCOPE_LIST>
d["program_scope"]["out_of_scope_vuln_classes"] = <OOS_VULN_CLASSES>
d["program_scope"]["scope_fetched_at"] = datetime.datetime.utcnow().isoformat() + "Z"

with open(findings_path, "w") as f:
    json.dump(d, f, indent=2)
print("[hackerone-api] findings.json updated")
PYEOF
```

---

## TTL Check (24h Cache)

Before any query, check if intel is fresh:

```bash
python3 << 'PYEOF'
import json, datetime, os

findings_path = "<output_dir>/findings.json"
d = json.load(open(findings_path))
fetched_at = d.get("h1_intel", {}).get("fetched_at")

if fetched_at:
    age = datetime.datetime.utcnow() - datetime.datetime.fromisoformat(fetched_at.replace("Z",""))
    if age.total_seconds() < 86400:
        print(f"SKIP_FETCH age={int(age.total_seconds()/3600)}h")
    else:
        print(f"STALE age={int(age.total_seconds()/3600)}h")
else:
    print("NO_CACHE")
PYEOF
```

If output is `SKIP_FETCH` — skip all queries and read from existing `h1_intel`. If `STALE` or `NO_CACHE` — run full query sequence.
