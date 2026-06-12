# Lean JavaScript Bug Bounty Pipeline

An automated, multi-phase static analysis workflow for bug bounty hunters — built on [OpenCode](https://opencode.ai). Given a directory of downloaded JavaScript bundles, this pipeline runs a sequence of specialized LLM agents to produce a hunter-ready bug bounty report with minimal token waste.

## Pipeline Overview

| Phase | Agent | Output | What It Does |
|-------|-------|--------|-------------|
| **0** | `js-bb-context` | `findings.json:bb_context` | Researches the target's bug bounty program, prior art (dupe risk per vuln class), and out-of-scope classes. Web-enabled. |
| **1** | `js-inventory-secrets` | `Secrets.md` | Decodes source maps (`.js.map` → original source), runs TruffleHog + grep for secrets, extracts staging/internal URLs and env references. |
| **2** | `js-api-mapper` | `Endpoints.md` | Full API surface extraction — REST endpoints, base URLs, WebSocket connections, client-side routes, and GraphQL operations. Flags IDOR, AUTH, UPLOAD, ADMIN, REDIRECT candidates. |
| **3** | `js-taint-analyzer` | `Taint.md` | Static source-to-sink taint analysis, prototype pollution detection, postMessage origin validation, CSRF analysis, service worker inspection, and DOM purifier version detection. |
| **4** | `js-attack-chain-synthesis` | `Report.md` | Synthesizes all prior phases into BB-calibrated attack chains, hunting strategies, a prioritized roadmap, and a kill list. |
| **5** | `js-caido-handoff` | Caido workspace | Stages Replay sessions for chain-matching HTTP requests and Automate rules for IDOR/BRUTE/ENUM clusters in Caido. No requests sent. |

## Architecture

```
.opencode/
├── agents/
│   ├── js-orchestrator.md         # Primary agent — entry point, runs phases 0-5 sequentially
│   ├── js-bb-context.md           # Phase 0: program research
│   ├── js-inventory-secrets.md    # Phase 1: source maps + secrets
│   ├── js-api-mapper.md           # Phase 2: API extraction
│   ├── js-taint-analyzer.md       # Phase 3: taint analysis
│   ├── js-attack-chain-synthesis.md # Phase 4: report synthesis
│   └── js-caido-handoff.md        # Phase 5: Caido workspace setup
├── tools/
│   └── render_reports.py          # Deterministic Python renderer — zero LLM tokens
├── skills/
│   ├── decode-sourcemaps/         # Source map decoding workflow
│   ├── graphql-mapper/            # GraphQL operation extraction
│   ├── service-worker-checker/    # Service worker fetch interception analysis
│   └── caido-mode/                # Caido SDK integration for workspace handoff
└── package.json                   # Dependencies: source-map, @opencode-ai/plugin
```

## Prerequisites

- **OpenCode** with internet-connected LLM access (the pipeline uses `opencode/deepseek-v4-flash-free`, `opencode/big-pickle`, and `nvidia/openai/gpt-oss-120b`)
- **Python 3.10+** with `json`, `re`, `os`, `sys`, `argparse` (stdlib only — no pip deps needed for the renderer)
- **Node.js 18+** and `npm` (for source-map decoding — `source-map` package is bundled)
- **TruffleHog** (for secrets detection in Phase 1)
- **Caido** (optional — only needed for Phase 5 workspace handoff)

## Usage

Run the orchestrator from OpenCode:

```
@js-orchestrator JS files directory: <path/to/js/files> Output directory: <path/to/output>
```

Required parameters:
- `JS files directory` — absolute path to the directory containing downloaded JS bundles (these are typically saved from Caido or a browser)
- `Output directory` — where all findings, reports, and intermediate JSON will be written

Optional parameters:
- `Target domain` — the root domain being analyzed (e.g. `example.com`). Auto-inferred from the output directory name if omitted.
- `Context` — hunter-provided notes (domain mappings, architecture quirks, etc.) injected verbatim into every agent prompt.

### Example

```
@js-orchestrator JS files directory: /home/hunter/app-analysis/MyFitnessPal/JS Output directory: /home/hunter/app-analysis/MyFitnessPal
```

### Output Structure

```
<output_dir>/
├── findings.json          # All structured data (endpoints, taint paths, secrets, bb_context, etc.)
├── Endpoints.md           # Phase 2 — API surface, grouped by category, with Top 10 table
├── Secrets.md             # Phase 1 — confirmed secrets + candidates + staging URLs
├── Taint.md               # Phase 3 — sources, sinks, taint paths, postMessage, CSRF, prototype pollution
├── Report.md              # Phase 4 — attack chains, hunting strategy, kill list
└── BBContext.md           # Phase 0 — program info, prior art, out-of-scope (optional, via --only bbcontext)
```

## Key Design Decisions

### Zero Token Waste
The pipeline is engineered to minimize LLM token consumption:
- **Phase 0** extracts exactly two things (prior art dupe risk, out-of-scope classes) — no program descriptions, no bounty tables, no submission rules
- **`render_reports.py`** generates all markdown files from `findings.json` using pure Python — zero LLM tokens spent on formatting
- Agents write to `findings.json` (structured JSON), not markdown; the renderer handles all presentation
- Attack chain synthesis is the only phase that produces a full narrative report

### Schema Validation
The renderer enforces a strict schema on `findings.json`:
- Endpoints require: `method`, `path`, `file`, `line`, `flags`, `bb_potential`, `first_test`, `category`, `ep_type`
- Taint paths require: `id`, `source_type`, `sink_type`, `source_file`, `source_line`, `sink_file`, `sink_line`, `confidence`, `estimated_bounty`
- Secrets require: `type`, `file`, `line`, `value_redacted`, `confirmed`
- Maximum 2000 endpoints and 500 taint paths — prevents runaway extraction and hallucination loops

### Hunter-Calibrated Output
Every endpoint includes a `bb_potential` rating (CRITICAL / HIGH / MEDIUM / LOW / INFO) and a `first_test` field describing exactly what to try first in Burp/Caido. The synthesis phase builds BB-calibrated attack chains that answer the question: *"What do I actually test next?"*

### Caido Integration (Phase 5)
The optional Caido handoff stages the workspace with:
- One Replay collection per program
- Replay sessions for chains where matching HTTP requests exist in Caido history
- Automate sessions for numeric/UUID IDOR clusters and BRUTE/ENUM chains
- Browser-only chains (postMessage/XSS without a clear HTTP endpoint) are skipped — no wrong sessions

## TO-DO
- Fix Caido handoff, currently its not that precise, the agent needs to be given a bit more freedom
