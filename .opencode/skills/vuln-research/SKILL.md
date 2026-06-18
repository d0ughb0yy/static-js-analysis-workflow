# Vuln Research Skill

Use this skill when performing the centralized intel gathering phase. It runs in parallel with `hackerone-api` — not as a fallback. Its role is technique-level knowledge: how vulnerabilities are exploited, what variants exist, what bypasses work, what the security community has published recently. H1 intel gives you target history; this gives you attack methodology.

Results are stored in `h1_intel.vuln_research` in findings.json, keyed by vulnerability category, with a 24h TTL matching the H1 intel cache.

---

## When to Run

Check TTL before running (same check as hackerone-api):

```bash
python3 << 'PYEOF'
import json, datetime

findings_path = "<output_dir>/findings.json"
d = json.load(open(findings_path))
fetched_at = d.get("h1_intel", {}).get("vuln_research_fetched_at")

if fetched_at:
    age = datetime.datetime.utcnow() - datetime.datetime.fromisoformat(fetched_at.replace("Z",""))
    if age.total_seconds() < 86400:
        print(f"SKIP_FETCH age={int(age.total_seconds()/3600)}h")
    else:
        print("STALE")
else:
    print("NO_CACHE")
PYEOF
```

If `SKIP_FETCH` — skip all searches, use cached `h1_intel.vuln_research`.

---

## Search Strategy

Two passes per vulnerability category found in `findings.json` attack chains:

**Pass 1 — Target-specific writeups:**
Search for disclosed vulnerabilities and writeups specific to this target.

Query pattern:
```
"<target_name>" "<vuln_category>" (site:hackerone.com OR site:bugcrowd.com OR site:medium.com OR site:github.com)
```

Examples:
```
"SoundCloud" "IDOR" site:hackerone.com
"MyFitnessPal" "authentication bypass" writeup
"Spotify" "GraphQL" bug bounty disclosed
```

**Pass 2 — Technique-level research:**
Search for methodology, bypasses, and techniques for this vulnerability class regardless of target.

Query pattern:
```
"<vuln_category>" bypass technique <year> (site:portswigger.net OR site:hacktricks.xyz OR site:owasp.org OR writeup)
```

Examples:
```
IDOR bypass UUID prediction 2024
JWT algorithm confusion attack technique
GraphQL introspection bypass WAF
CSRF SameSite bypass 2024
mass assignment API hidden fields technique
```

---

## Vulnerability Category to Search Terms Mapping

```
idor        → ["IDOR", "BOLA", "insecure direct object reference", "broken object level authorization"]
auth        → ["authentication bypass", "auth bypass", "session hijack", "broken authentication"]
csrf        → ["CSRF", "cross-site request forgery", "SameSite bypass", "CSRF token bypass"]
graphql     → ["GraphQL injection", "GraphQL IDOR", "GraphQL introspection", "GraphQL batch attack"]
mass        → ["mass assignment", "parameter pollution", "hidden parameter", "undocumented field"]
jwt         → ["JWT attack", "algorithm confusion", "none algorithm", "JWT secret bruteforce", "kid injection"]
admin       → ["admin panel exposure", "privilege escalation", "broken access control", "admin bypass"]
```

Use the primary term first, then augment with alternatives if the first search returns fewer than 3 useful results.

---

## What to Extract from Results

For each search result, extract only actionable content:

**From HackerOne disclosed reports:**
- Vulnerability description (1-2 sentences)
- Reproduction steps summary (not verbatim — key steps only)
- Severity rating
- Was it accepted/bounty paid? (signals real exploitability)
- Any interesting bypass or technique mentioned

**From PortSwigger / HackTricks / OWASP:**
- Technique name
- Core mechanism (how the vuln works)
- Detection method (what to look for in traffic/responses)
- Key payloads or proof-of-concept pattern (brief, not full payload lists)
- Mitigations (helps understand what might be in place)

**From blog posts / writeups:**
- Target type (similar app architecture?)
- What the hunter noticed that led to the finding
- Endpoint pattern or parameter that was vulnerable
- Impact

Do NOT extract: full payload lists, complete reproduction steps verbatim, large code blocks. Summarize in 3-5 bullet points per source.

---

## Result Quality Filter

Before storing a result, check:

- Is it relevant to the specific vuln category? (discard tangential results)
- Is it from a credible source? (H1/Bugcrowd disclosure, PortSwigger, OWASP, known security researchers)
- Does it contain actionable technique information? (not just theory)
- Is it recent enough to be relevant? (prefer last 3 years, flag if older)

Discard results that are:
- Pure theory with no exploitation path
- Marketing content or vendor blogs without technical depth
- Duplicate of already-stored technique
- Behind paywalls (can't extract content)

---

## Output Format

Store per-category research as structured objects, not raw text:

```python
vuln_research_entry = {
    "category": "idor",
    "target_writeups": [
        {
            "source": "hackerone.com/reports/123456",
            "title": "IDOR in /api/v2/users/{id}/profile",
            "severity": "high",
            "key_technique": "Sequential integer ID with no ownership check",
            "accepted": True
        }
    ],
    "techniques": [
        {
            "source": "portswigger.net",
            "name": "IDOR via indirect references",
            "mechanism": "Application uses predictable references (sequential IDs, hashed values) without server-side ownership validation",
            "detection": "Change object ID in request to another user's known ID, compare response",
            "notes": "Hash-based IDs (MD5/SHA of email) are still guessable given known inputs"
        }
    ],
    "bypass_patterns": [
        "Wrap ID in array: user_id=123 → user_id[]=123",
        "JSON type juggling: \"id\": \"123\" vs \"id\": 123",
        "Try v1 endpoint if v2 has fix: /api/v1/users/123"
    ]
}
```

---

## findings.json Write Pattern

```bash
python3 << 'PYEOF'
import json, datetime

findings_path = "<output_dir>/findings.json"
d = json.load(open(findings_path))

if "h1_intel" not in d:
    d["h1_intel"] = {}

if "vuln_research" not in d["h1_intel"]:
    d["h1_intel"]["vuln_research"] = {}

# Merge by category — never overwrite existing entries unless stale
for category, data in <RESEARCH_RESULTS_DICT>.items():
    d["h1_intel"]["vuln_research"][category] = data

d["h1_intel"]["vuln_research_fetched_at"] = datetime.datetime.utcnow().isoformat() + "Z"

with open(findings_path, "w") as f:
    json.dump(d, f, indent=2)
print("[vuln-research] findings.json updated")
PYEOF
```

---

## Interaction with Claude-BugHunter Hunt Skills

This skill and the Claude-BugHunter `hunt-*` skills are partners, not substitutes:

- **hunt-* skills** provide the *methodology* — 681 disclosed-report patterns, technique decision trees, how to approach each vuln class, what to test and in what order
- **vuln-research** provides *current intelligence* — what's been found on this specific target before, what bypasses are trending right now, target-specific writeups the static patterns won't cover

When a probe agent picks up a chain, it loads the relevant `hunt-*` skill for methodology and reads `h1_intel.vuln_research[category]` for current context. Both inform the probing strategy together.

---

## Search Execution Notes

- Run searches sequentially, not in parallel — avoid triggering rate limits on search APIs
- 2-3 searches per vulnerability category maximum in a single run
- If the same technique appears across multiple sources, store it once with multiple source references
- Always note the search date in the stored result so staleness can be assessed on re-run
- If no useful results found for a category after 2 searches, store `{"category": "<cat>", "no_results": true}` and move on — do not retry indefinitely
