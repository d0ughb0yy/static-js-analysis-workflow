---
name: service-worker-checker
description: Called by js-taint-analyzer when service worker files are detected. Analyzes fetch interception, cache strategies, skipWaiting/clients.claim patterns, message passing, and auth token exposure. Generates cache poisoning and auth bypass test cases. Use when sw.js, service-worker.js, or files containing self.addEventListener/caches.open are found.
---

# Service Worker Checker Skill

Called inline by `js-taint-analyzer` when service worker files are detected. Read the SW files identified by the detection step and follow these instructions. Append results to `Taint.md` under `## Service Worker`.

Think like a hunter. Service workers are high-value surface that most hunters skip. The two best outcomes from this analysis: (1) auth responses cached post-logout = session persistence after logout, (2) unversioned third-party importScripts = supply chain escalation path. Everything else is secondary. Lead with these two when writing findings.

---

## Step 1 — Read the Service Worker Files

For each SW file found, read it in sections — do not cat the entire file at once:
```bash
sed -n '1,100p' "<js_dir>/sw.js"
```

---

## Step 2 — Fetch Event Handler Analysis

```bash
LC_ALL=C grep -rn --include="*.js" -E "addEventListener\(['\"]fetch['\"]" "<js_dir>" 2>/dev/null
```

For each fetch handler, check:
- What URLs are intercepted (regex, string match, prefix)
- Whether auth endpoints are in scope (`/api/auth`, `/oauth`, `/login`, `/token`)
- Whether `Authorization` or `Cookie` headers are injected into forwarded requests
- Whether responses are cached without status code check (`cache.put` without `response.ok`)
- Whether `event.request` is consumed without `.clone()`

**Risk patterns to flag:**
- Intercepting auth endpoints and caching responses → **CACHE AUTH DATA** — test post-logout session persistence
- Adding auth headers to all outgoing requests → **TOKEN EXPOSURE TO THIRD PARTIES** if scope is too broad
- `cache.put(request, response)` without checking `response.status === 200` → **CACHES ERROR RESPONSES**

---

## Step 3 — Cache Strategy Analysis

```bash
LC_ALL=C grep -rn --include="*.js" -E "caches\.open|caches\.match|caches\.put|cache\.add|cache\.addAll|cache\.put" "<js_dir>" 2>/dev/null
```

Classify each usage:
- **Cache First** — return cache, fetch if missing → stale/poisoned cache risk
- **Network First** — fetch, cache response → may cache 4xx/5xx responses
- **Stale While Revalidate** → serves stale after expiry
- **Cache Only** → update path may be broken

Flag: POST/PUT/DELETE responses being cached; `cache.addAll([...])` with user-controllable URLs; no cache expiry or cleanup logic.

---

## Step 4 — skipWaiting and clients.claim

```bash
LC_ALL=C grep -rn --include="*.js" -E "skipWaiting|clients\.claim" "<js_dir>" 2>/dev/null
```

Both present together = new SW immediately takes control of all tabs without page reload. Flag if combined with aggressive caching — could serve poisoned cached responses to active sessions.

---

## Step 5 — Third-Party Script Imports

```bash
LC_ALL=C grep -rn --include="*.js" -E "importScripts\s*\(" "<js_dir>" 2>/dev/null
```

Critical supply chain risk. If `importScripts()` loads from an external CDN, attacker code running with full SW privileges is one CDN compromise away.

For each `importScripts()` call, classify:
- **FIRST-PARTY** — same origin or self-hosted CDN → Low
- **THIRD-PARTY VERSIONED** — external CDN with pinned hash or semver → Medium
- **THIRD-PARTY UNVERSIONED** — external CDN with `latest`, `main`, or no version pin → **CRITICAL**

---

## Step 6 — Message Passing

```bash
LC_ALL=C grep -rn --include="*.js" -E "addEventListener\(['\"]message['\"]" "<js_dir>" 2>/dev/null
```

For each message handler in SW context (`self.addEventListener`), check:
- What operations can be triggered (cache clear, forced fetch, state change)
- Whether `event.origin` is validated before acting
- Whether message data is used directly without sanitization

---

## Step 7 — Auth Token Exposure

```bash
LC_ALL=C grep -rn --include="*.js" -E "Authorization|Bearer|Cookie|jwt|token" "<js_dir>/sw.js" 2>/dev/null
```

Flag any auth tokens stored in `CacheStorage` or `IndexedDB` within the SW — these persist across sessions.

---

## Step 8 — Write Service Worker Section

**Always use Python for all file writes.** Never use printf, echo, or heredoc.

**Never use `python3 -c "..."`** for any write that contains backticks, angle brackets, or special characters in the content. Bash interprets backticks as command substitution and angle brackets as redirects *before* Python sees the string.

**Always write to a temp script file and execute it:**
```bash
cat > /tmp/write_block.py << 'PYEOF'
with open("<output_file>", "a") as f:
    f.write("| \`file.js\` | 4.4 MB | main | MINIFIED | No |\n")
    f.write("| <script>test</script> | example |\n")
PYEOF
python3 /tmp/write_block.py
```

The heredoc with a quoted delimiter (`<< 'PYEOF'`) passes the Python source verbatim — bash performs zero substitution. Backticks, angle brackets, dollar signs, and all markdown special characters are safe. Use this pattern for **every** write call without exception.

```bash
cat > /tmp/write_block.py << 'PYEOF'
rows = [
    ('sw.js', '42 KB', '/'),
]
with open('<output_file>', 'a') as f:
    f.write('### Service Worker Files\n\n')
    f.write('| File | Size | Scope |\n')
    f.write('|------|------|-------|\n')
    for r in rows:
        f.write('| {} | {} | {} |\n'.format(*r))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
rows = [
    ('https://cdn.example.com/sw.latest.js', 'No (latest)', 'External CDN', 'CRITICAL', 'Unversioned external import — full SW privilege escalation on CDN compromise'),
]
with open('<output_file>', 'a') as f:
    f.write('### Third-Party Script Imports\n\n')
    f.write('| URL | Versioned | Source | Severity | Notes |\n')
    f.write('|-----|-----------|--------|----------|-------|\n')
    for r in rows:
        f.write('| {} | {} | {} | {} | {} |\n'.format(*r))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
rows = [
    ('GET_VERSION_REQUEST', 'sw.js', '45', 'No (SW security model)', 'Returns static version string', 'Low'),
]
with open('<output_file>', 'a') as f:
    f.write('### Message Handling\n\n')
    f.write('| Message Type | Handler File | Line | Origin Validated | Operations Triggered | Risk |\n')
    f.write('|-------------|-------------|------|-----------------|---------------------|------|\n')
    for r in rows:
        f.write('| {} | {} | {} | {} | {} | {} |\n'.format(*r))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
with open('<output_file>', 'a') as f:
    f.write('### Fetch Interception\n\n')
    f.write('| Intercepted URLs | Auth Endpoints in Scope | Headers Modified | Cache Behavior | Risk |\n')
    f.write('|-----------------|------------------------|-----------------|----------------|------|\n\n')
    f.write('### Cache Strategy Risks\n\n')
    f.write('| Strategy | Endpoint | Risk | File | Line |\n')
    f.write('|----------|----------|------|------|------|\n\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
with open('<output_file>', 'a') as f:
    f.write('### Manual Test Cases\n\n')
    f.write('**Cache Poisoning - Auth Response:**\n')
    f.write('1. Login (SW caches /api/me)\n')
    f.write('2. Logout\n')
    f.write('3. Revisit app — does SW serve cached /api/me without a live session?\n')
    f.write('4. If yes: cached user data accessible post-logout — submittable as auth bypass\n\n')
    f.write('**skipWaiting Disruption:**\n')
    f.write('1. Open app in two tabs\n')
    f.write('2. Trigger SW update in tab 1\n')
    f.write('3. Check if tab 2 session is disrupted (stale cached data served)\n\n')
    f.write('**Third-Party importScripts (if CRITICAL found):**\n')
    f.write('1. Document the exact CDN URL and version pinning status\n')
    f.write('2. Check if the CDN package has had any prior compromise history\n')
    f.write('3. Report as supply chain risk with full SW privilege escalation impact\n\n')

PYEOF
python3 /tmp/write_block.py
```
