---
name: graphql-mapper
description: Called by js-api-mapper when GraphQL client patterns are detected in JS files. Extracts GraphQL operations, fragments, type references, and generates manual introspection test queries from static JS artifacts. Never sends live requests. Use when grep results contain apollo, relay, urql, graphql-tag, gql, __typename, IntrospectionQuery, or /graphql URL patterns.
---

# GraphQL Mapper Skill

This skill is invoked **only** when `js-api-mapper` detects GraphQL patterns. It runs inline within that agent — not as a separate subagent.

The agent reads this file and follows the instructions below, then appends a `## GraphQL` section to `Endpoints.md`.

Think like a hunter throughout. GraphQL is high-value surface — introspection gives you the full schema, mutations are often IDOR-able by object ID, and batch operations can bypass rate limits. Every operation you find should be evaluated for what a hunter would try first, not just catalogued.

---

## When to Run

Run if ANY Set C grep result matched:
- Files with `apollo`, `relay`, `urql`, `graphql-tag`, `gql`, `__typename`, `IntrospectionQuery`
- Any match on `/graphql`, `graphql_url`, `GRAPHQL_URL`

If all Set C greps returned zero results, write `## GraphQL\n\nNot detected.` and skip this skill entirely.

---

## Step 1 — Find the Endpoint

```bash
LC_ALL=C grep -rn --include="*.js" -E "/graphql|graphql_url|GRAPHQL_URL|gql_host|graphqlUri" "<js_dir>" 2>/dev/null | head -20
```

Record all unique GraphQL endpoint URLs found.

---

## Step 2 — Extract Operations

Each grep is a separate bash call.

**Tagged template literals:**
```bash
LC_ALL=C grep -rn --include="*.js" -A 5 -E "gql\`|graphql\`" "<js_dir>" 2>/dev/null | head -200
```

**Inline operation strings:**
```bash
LC_ALL=C grep -rn --include="*.js" -E "query\s+[A-Z][a-zA-Z]+\s*[\({]|mutation\s+[A-Z][a-zA-Z]+\s*[\({]|subscription\s+[A-Z][a-zA-Z]+\s*[\({]" "<js_dir>" 2>/dev/null | head -100
```

**Fragment definitions:**
```bash
LC_ALL=C grep -rn --include="*.js" -E "fragment\s+[A-Z][a-zA-Z]+\s+on\s+[A-Z][a-zA-Z]+" "<js_dir>" 2>/dev/null | head -100
```

For each operation, extract: type (Query/Mutation/Subscription), name, variables and types, top-level fields selected.

---

## Step 3 — Extract Type References

```bash
LC_ALL=C grep -rn --include="*.js" -E "__typename|on [A-Z][a-zA-Z]+" "<js_dir>" 2>/dev/null | head -100
```
```bash
LC_ALL=C grep -rn --include="*.js" -E "[A-Z][a-zA-Z]+(Input|Payload|Args)\b" "<js_dir>" 2>/dev/null | head -50
```

Collect unique type names to partially reconstruct the schema without introspection.

---

## Step 4 — Flag High-Interest Operations

| Flag | Condition |
|------|-----------| 
| `IDOR` | Takes `id`, `userId`, `accountId`, `objectId` as variable |
| `ADMIN` | Name or fields contain `admin`, `internal`, `debug`, `manage`, `delete` |
| `FILE` | Variables reference `upload`, `file`, `attachment`, `media`, `avatar` |
| `AUTH` | Relates to `login`, `register`, `token`, `session`, `invite`, `permission` |
| `BATCH` | Multiple operations bundled in one document |

**Hunter notes per flag:**
- `IDOR` — swap the ID variable to another user's object ID; GraphQL often skips authorization on nested resolvers even when the top-level query is protected
- `ADMIN` — test as a non-admin user; GraphQL introspection may expose admin mutations even if the UI hides them
- `BATCH` — send 100 operations in one request; many rate limiters count requests not operations
- `AUTH` — look for account enumeration via error message differences between valid and invalid identifiers

---

## Step 5 — Manual Test Queries

**Full introspection:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { kind name description
      fields(includeDeprecated: true) { name
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name } }
      }
    }
  }
}
```

**Quick type list (often works when full introspection is disabled):**
```graphql
{ __schema { types { name kind } } }
```

**Field enumeration for a known type:**
```graphql
{ __type(name: "User") { fields { name type { name kind } } } }
```

**IDOR test for an ID-taking operation (substitute real operation name and ID):**
```graphql
query { getUser(id: "OTHER_USER_ID") { email phone billingInfo } }
```

---

## Step 6 — Write GraphQL Section to Endpoints.md

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
with open('<output_file>', 'a') as f:
    f.write('\n## GraphQL\n\n')
    f.write('### Endpoint\n\n')
    f.write('| URL | File | Line |\n')
    f.write('|-----|------|------|\n')
    f.write('| https://api.example.com/graphql | main.js | 42 |\n\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
rows = [
    ('Query', 'GetUser', 'id: ID!', 'IDOR', 'app.js', '88'),
    ('Mutation', 'DeleteRecord', 'id: ID!', 'IDOR ADMIN', 'app.js', '142'),
]
with open('<output_file>', 'a') as f:
    f.write('### Operations\n\n')
    f.write('| Type | Name | Variables | Flags | File | Line |\n')
    f.write('|------|------|-----------|-------|------|------|\n')
    for r in rows:
        f.write('| {} | {} | {} | {} | {} | {} |\n'.format(*r))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
rows = [
    ('User', '__typename match', 'app.js', '201'),
    ('UserInput', 'mutation variable', 'app.js', '88'),
]
with open('<output_file>', 'a') as f:
    f.write('### Type References\n\n')
    f.write('| Type | Context | File | Line |\n')
    f.write('|------|---------|------|------|\n')
    for r in rows:
        f.write('| {} | {} | {} | {} |\n'.format(*r))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```

Paste the introspection queries from Step 5 as fenced code blocks directly into the file:

```bash
cat > /tmp/write_block.py << 'PYEOF'
with open('<output_file>', 'a') as f:
    f.write('### Manual Introspection Queries\n\n')
    f.write('Try full introspection first. If blocked, try the quick type list.\n\n')
    f.write('See Step 5 above for query bodies.\n\n')

PYEOF
python3 /tmp/write_block.py
```

```bash
cat > /tmp/write_block.py << 'PYEOF'
gaps = [
    'Introspection may be disabled in production — try quick type list fallback',
    'Persisted queries may hide operation names — check for persisted query ID pattern',
    'Field-level authorization not visible statically — test each IDOR-flagged operation dynamically',
    'Batch operation rate limiting not verifiable statically',
]
with open('<output_file>', 'a') as f:
    f.write('### Evidence Gaps\n\n')
    for g in gaps:
        f.write('- [ ] {}\n'.format(g))
    f.write('\n')

PYEOF
python3 /tmp/write_block.py
```
