# Prior Art Lookup Skill

Use this skill to find which bug bounty platform/program a target belongs to, what's in/out of scope, and a rough dupe-risk signal per vulnerability class based on publicly disclosed reports. Everything here is unauthenticated and non-blocking — no API token required, no rate-limit risk that can stall a run.

This is deliberately simpler than the `hackerone-api` skill (which needs `HACKERONE_API_TOKEN` and is used by the Caido ecosystem for live-traffic prioritization). This skill exists for a cheaper, zero-setup lookup that runs once per target at the start of the JS pipeline.

---

## Step 1 — Program Lookup via bounty-targets-data

`bounty-targets-data` is an hourly-updated, unauthenticated mirror of public scope tables across four platforms. No scraping, no bot detection, no rate limits.

```bash
cat > /tmp/pal_lookup.py << 'PYEOF'
import json, urllib.request, sys

TARGET = "<target_domain_or_name>"  # e.g. "myfitnesspal.com" or "MyFitnessPal"
name_lower = TARGET.lower().replace(".com","").replace(".io","").replace(".net","").replace(".org","")

SOURCES = [
    ("hackerone",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"),
    ("bugcrowd",   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"),
    ("intigriti",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json"),
    ("yeswehack",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json"),
]

result = {"platform": None, "program": None, "in_scope": [], "out_of_scope": []}

for platform, url in SOURCES:
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"WARN: could not fetch {platform}: {e}", file=sys.stderr)
        continue
    for entry in data:
        name = entry.get("name", "")
        handle = entry.get("handle", entry.get("url", ""))
        website = entry.get("website", "")
        check = f"{name} {handle} {website}".lower()
        if name_lower in check or TARGET.lower() in check:
            result["platform"] = platform
            result["program"] = {"name": name, "url": entry.get("url", handle),
                                  "offers_bounties": entry.get("offers_bounties", entry.get("max_payout") is not None)}
            targets = entry.get("targets", {})
            result["in_scope"] = targets.get("in_scope", [])
            result["out_of_scope"] = targets.get("out_of_scope", [])
            break
    if result["platform"]:
        break

with open("/tmp/pal_lookup_result.json", "w") as f:
    json.dump(result, f, indent=2)

if result["platform"]:
    print(f"FOUND: {result['program']['name']} on {result['platform']}")
    print(f"  in_scope entries:     {len(result['in_scope'])}")
    print(f"  out_of_scope entries: {len(result['out_of_scope'])}")
else:
    print("NOT FOUND in any platform — dupe risk and out-of-scope hosts will be UNKNOWN/empty")
PYEOF
python3 /tmp/pal_lookup.py
```

If `Target domain` is unknown/empty, skip this step entirely and go straight to the Write Pattern below with everything empty — do not guess.

---

## Step 2 — Prior Art via H1 Public Disclosed Reports (HackerOne only)

Only runs if Step 1 found `platform == "hackerone"`. This is the public, unauthenticated reports endpoint — not the GraphQL API, no token needed.

```bash
cat > /tmp/pal_prior_art.py << 'PYEOF'
import json, urllib.request, re

d = json.load(open("/tmp/pal_lookup_result.json"))
platform = d.get("platform", "")
program = d.get("program", {})

VULN_KEYWORDS = {
    "IDOR":            r"idor|insecure.?direct.?object|broken.?access|bac",
    "XSS":             r"\bxss\b|cross.?site.?script",
    "SSRF":            r"\bssrf\b|server.?side.?request.?forg",
    "SQLI":            r"sql.?inject|sqli",
    "AUTH_BYPASS":     r"auth.?bypass|authentication.?bypass|jwt|alg.?none|account.?takeover|ato",
    "OPEN_REDIRECT":   r"open.?redirect|unvalidated.?redirect",
    "INFO_DISCLOSURE": r"info.?disclos|sensitive.?data|pii.?leak|data.?exfil|information.?leak",
    "CSRF":            r"\bcsrf\b|cross.?site.?request.?forg",
    "PROTO_POLLUTION": r"proto.?pollut|prototype.?pollut",
    "POSTMESSAGE":     r"postmessage|post.?message",
}

counts = {k: 0 for k in VULN_KEYWORDS}

if platform == "hackerone" and program:
    handle = program.get("url", "").rstrip("/").split("/")[-1]
    try:
        api_url = f"https://hackerone.com/programs/{handle}/reports?disclosed=true&limit=100"
        req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            reports = json.loads(r.read())
        titles = [rpt.get("title", "") + " " + rpt.get("vulnerability_information", "") for rpt in reports.get("data", [])]
        print(f"Fetched {len(titles)} disclosed reports for {handle}")
        for text in titles:
            tl = text.lower()
            for vuln, pattern in VULN_KEYWORDS.items():
                if re.search(pattern, tl):
                    counts[vuln] += 1
    except Exception as e:
        print(f"HackerOne reports API unavailable: {e} — dupe risk UNKNOWN")
else:
    print(f"Platform: {platform or 'none'} — no machine-readable prior art source, dupe risk UNKNOWN")

with open("/tmp/pal_prior_art_result.json", "w") as f:
    json.dump(counts, f, indent=2)

for k, v in sorted(counts.items(), key=lambda x: -x[1]):
    if v > 0:
        print(f"  {k}: {v}")
PYEOF
python3 /tmp/pal_prior_art.py
```

If the call fails or platform isn't HackerOne, every class stays at count 0 — that maps to `UNKNOWN`, not `NOVEL`. Don't conflate "we don't know" with "nobody's found this before."

---

## Dupe Risk Bucketing

| Count (last ~100 disclosed reports) | Dupe Risk |
|---|---|
| 5+ | HIGH |
| 2–4 | MEDIUM |
| 1 | LOW |
| 0 (lookup succeeded) | NOVEL |
| lookup failed / not H1 | UNKNOWN |

---

## Output

Read back `/tmp/pal_lookup_result.json` and `/tmp/pal_prior_art_result.json` and merge into a single `program_intel` object the calling agent writes to `findings.json:meta.program_intel`:

```json
{
  "platform": "hackerone",
  "program_name": "MyFitnessPal",
  "offers_bounties": true,
  "out_of_scope_hosts": ["community.myfitnesspal.com", "community-stage.myfitnesspal.com"],
  "dupe_risk_by_class": {"IDOR": "MEDIUM", "XSS": "LOW", "SSRF": "UNKNOWN"}
}
```

`out_of_scope_hosts` should merge `out_of_scope` entries from Step 1 with anything the hunter already pasted in `[HUNTER CONTEXT]` — hunter input always wins on conflict, it's more current than an hourly-cached mirror.

Everything in this object is informational. Nothing here should ever block or fail a run — a target not found on any platform, or a failed network call, just means UNKNOWN values, not an error.
