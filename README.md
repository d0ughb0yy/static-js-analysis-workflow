# JS Bug Bounty Pipeline + Caido Hunting Ecosystem

Two independent ecosystems for bug bounty hunters, built on [OpenCode](https://opencode.ai).

The **JS pipeline** takes a directory of downloaded JavaScript bundles and runs multi-phase static analysis to produce structured findings and hunter-ready reports. The **Caido ecosystem** reads the pipeline output, layers in live HTTP traffic, active probing, and prior-art intel, then produces confirmed findings ready for submission.

## JS Pipeline

| Phase | Agent | Output | What It Does |
|-------|-------|--------|-------------|
| **0** | `js-discovery` | `findings.json:meta.program_intel` | Identifies the bug bounty platform/program, merges out-of-scope hosts, computes dupe-risk per vuln class. Non-blocking — degrades gracefully to UNKNOWN. |
| **1** | `js-inventory-secrets` | `findings.json:secrets` → `Secrets.md` | Decodes source maps (`.js.map` → original source via `sourcemapper`), runs TruffleHog + grep for secrets, extracts staging/internal URLs, `process.env` and `import.meta.env` references, plus subdomain takeover candidates. |
| **2** | `js-api-mapper` | `findings.json:endpoints` → `Endpoints.md` | Full API surface extraction — REST endpoints with methods/paths, base URLs, WebSocket connections, client-side routes, GraphQL operations, and security flags (IDOR, AUTH, UPLOAD, ADMIN, REDIRECT). Every endpoint gets a `bb_potential` rating and a `first_test` action. |
| **3** | `js-sink-scanner` | `findings.json:sinks` → `Sinks.md` | Greps the JS bundle for dangerous sink call-sites (innerHTML, eval, dangerouslySetInnerHTML, jQuery DOM injection, Angular trust bypass, prototype pollution, navigation sinks, cookie readability). Does NOT trace data flow — writes a flat inventory for manual review. |

**Orchestrator:** `js-orchestrator` — runs Phases 0–3 sequentially with checkpoint/retry on each. Single entry point. Output: `findings.json` + `Secrets.md` + `Endpoints.md` + `Sinks.md`.

## Caido Hunting Ecosystem

A separate, independent ecosystem that reads the JS pipeline's output and actively hunts for confirmed vulnerabilities via Caido.

| Phase | Agent | What It Does |
|-------|-------|-------------|
| **1** | `caido-intel` | Resolves the program platform (HackerOne, Bugcrowd, etc.), fetches disclosed reports per-target and per-weakness-category, runs web-based vuln research for attack classes present in the chain list. 24h TTL cache. Never probes. |
| **2** | `caido-session-builder` | Reads attack chains and discoveries from `findings.json`, creates Caido Replay collections and sessions for every HTTP-testable chain. Keys sessions on `chain_id` for idempotent re-runs. Skips browser-only chains. |
| **3a** | `caido-probe-runner` | Runs targeted active probes (max 5 requests per chain) against staged sessions. Uses hunt-* skills + `h1_intel` as joint inputs. Probes IDOR (differential), AUTH (leak detection), ADMIN (unauthed access), CSRF, race conditions. Writes verdicts: CONFIRMED / NOT_VULNERABLE / NEEDS-MANUAL. |
| **3b** | `caido-discovery` | Inspects live Caido traffic to find endpoints and attack surfaces the JS pipeline never saw. Cross-references with `h1_intel` to prioritize. Probes interesting discoveries autonomously. |

**Orchestrator:** `caido-orchestrator` — runs Phases 1–3b sequentially (3a+3b in parallel) with idempotent merge. Requires Caido running with two account presets. Independent from the JS pipeline.

## Project Structure

```
.
├── .opencode/
│   ├── opencode.json              # OpenCode config (external dir permissions)
│   ├── package.json               # source-map + @opencode-ai/plugin deps
│   ├── agents/                    # Pipeline orchestrators + phase agents
│   │   ├── js-orchestrator.md     # JS pipeline entry point (Phases 0-3)
│   │   ├── js-discovery.md        # Phase 0 — program/prior-art discovery
│   │   ├── js-inventory-secrets.md# Phase 1 — source maps + secrets
│   │   ├── js-api-mapper.md       # Phase 2 — API endpoint extraction
│   │   ├── js-sink-scanner.md     # Phase 3 — dangerous sink inventory
│   │   ├── caido-orchestrator.md  # Caido ecosystem entry point
│   │   ├── caido-intel.md         # Caido Phase 1 — intel gathering
│   │   ├── caido-session-builder.md # Caido Phase 2 — Replay session staging
│   │   ├── caido-probe-runner.md  # Caido Phase 3a — active probing
│   │   └── caido-discovery.md     # Caido Phase 3b — live traffic discovery
│   ├── skills/                    # Reusable skills loaded by agents
│   │   ├── decode-sourcemaps/     # Source map → original source via sourcemapper
│   │   ├── graphql-mapper/        # GraphQL operation/fragment extraction
│   │   ├── hackerone-api/         # HackerOne disclosed report search
│   │   ├── prior-art-lookup/      # Dupe risk / prior art research
│   │   └── vuln-research/         # Web-based vulnerability research pass
│   └── tools/
│       └── render_reports.py      # Deterministic Python renderer — zero LLM tokens
├── .agents/
│   └── skills/                    # Skills from Claude-BugHunter (IDOR, XSS, SSRF, auth bypass, etc.)
├── patterns.json                  # Cross-program pattern library (findings database)
└── .gitignore
```

## Prerequisites

- **OpenCode** with LLM access (models used: `opencode/deepseek-v4-flash-free`, `opencode/big-pickle`, `nvidia/openai/gpt-oss-120b`, `opencode/mimo-v2.5-free`, `opencode/nemotron-3-ultra-free`)
- **Python 3.10+** (stdlib only — no pip deps)
- **Node.js 18+** and `npm` for source-map decoding
- **[sourcemapper](https://github.com/d4rkr00t/sourcemapper)** (JS pipeline Phase 1 — source map extraction)
- **TruffleHog** (JS pipeline Phase 1 — secrets detection)
- **Caido** with two account presets (Caido ecosystem Phase 2 onward)

## Usage

### JS Pipeline

```
@js-orchestrator JS files directory: <path/to/js/files> Output directory: <path/to/output>
```

Optional: `Target domain: example.com` and/or `Context: <hunter notes>`

Output:
```
<output_dir>/
├── findings.json       # All structured data (endpoints, secrets, sinks, etc.)
├── Secrets.md          # Confirmed secrets + candidates + staging URLs
├── Endpoints.md         # API surface grouped by category with Top 10 table
└── Sinks.md             # Dangerous sink inventory by category (innerHTML, eval, etc.)
```

### Caido Ecosystem

```
@caido-orchestrator Output directory: <path/to/output> Account 1 preset: <preset1> Account 2 preset: <preset2>
```

Requires a completed JS pipeline run in the output directory. Optional: `Focus: /api/v2/users`, `Out of scope vuln classes: csrf, rate limiting`, `Force intel refresh: true`.

## Key Design Decisions

### Zero Token Waste
- Agents write to `findings.json` (structured JSON), never markdown
- `render_reports.py` generates all markdown from JSON — pure Python, zero LLM tokens
- Strict schema validation enforces completeness (max 2000 endpoints, 2000 sinks)
- Phase 0 extracts exactly two things (prior art, OOS classes) — no filler

### Hunter-Calibrated Output
Every endpoint has a `bb_potential` rating (CRITICAL→INFO) and a `first_test` describing what to try first in Burp/Caido. The pipeline answers: *"What do I actually test next?"*

### Idempotent Reruns
All Caido agents merge by key — never overwrite. Sessions keyed on `chain_id`; intel cached with 24h TTL. Re-running only processes new/changed items.

### Layered Defense
- `program_scope.out_of_scope_vuln_classes` is a hard boundary — agents will not probe those
- `findings.json` merge guards prevent Phase 1 from writing endpoint/sink keys
- Phase agents each have distinct model assignments (low-temp for extraction, higher-temp for discovery)

### Cross-Program Pattern Library
`patterns.json` stores confirmed findings indexed by program. The synthesis reads it on every run for dupe-risk calibration. Add confirmed findings after submission to build an institutional memory.
