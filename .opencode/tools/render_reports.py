#!/usr/bin/env python3
"""
Deterministic report renderer for the JS bug bounty pipeline.
Reads findings.json and writes all markdown reports.
Zero LLM tokens — pure Python.

Usage:
    python3 render_reports.py --findings <findings.json> --output-dir <dir>
    python3 render_reports.py --findings <findings.json> --output-dir <dir> --merge <new_findings.json>
    python3 render_reports.py --findings <findings.json> --output-dir <dir> --only endpoints
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

REQUIRED_ENDPOINT_FIELDS = {"method", "path", "file", "line", "flags", "bb_potential", "first_test", "category", "ep_type"}
REQUIRED_TAINT_FIELDS = {"id", "source_type", "sink_type", "source_file", "source_line", "sink_file", "sink_line", "confidence", "estimated_bounty"}
REQUIRED_SECRET_FIELDS = {"type", "file", "line", "value_redacted", "confirmed"}
VALID_BB_POTENTIAL = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CONFIDENCE = {"CONFIRMED", "INFERRED", "BLOCKED"}
VALID_FLAGS = {"IDOR", "ADMIN", "UPLOAD", "REDIRECT", "AUTH", "EXPORT", "WEBSOCKET", "GRAPHQL"}
VALID_CATEGORIES = {
    "Auth & Identity", "Admin & Internal", "Data & Content",
    "File Upload / Export", "Billing & Payment",
    "Pub/Sub, Realtime & Promotions", "Integrations & Webhooks",
    "WebSocket", "GraphQL", "Uncategorized",
    "Base URLs & Environment Variables", "Client Routes",
}
VALID_EP_TYPES = {"server", "client_route", "websocket", "graphql"}
MAX_ENDPOINTS = 2000
MAX_TAINT_PATHS = 500

def validate_endpoint(ep: dict, idx: int) -> list[str]:
    errors = []
    missing = REQUIRED_ENDPOINT_FIELDS - set(ep.keys())
    if missing:
        errors.append(f"endpoint[{idx}] missing required fields: {sorted(missing)} -- path={ep.get('path','?')}")
    if ep.get("bb_potential") not in VALID_BB_POTENTIAL:
        errors.append(f"endpoint[{idx}] invalid bb_potential '{ep.get('bb_potential')}' -- path={ep.get('path','?')}")
    if ep.get("ep_type") not in VALID_EP_TYPES:
        errors.append(f"endpoint[{idx}] invalid ep_type '{ep.get('ep_type')}' -- path={ep.get('path','?')}")
    if ep.get("category") not in VALID_CATEGORIES:
        errors.append(f"endpoint[{idx}] invalid category '{ep.get('category')}' -- path={ep.get('path','?')}")
    for flag in ep.get("flags", []):
        if flag not in VALID_FLAGS:
            errors.append(f"endpoint[{idx}] unknown flag '{flag}' -- path={ep.get('path','?')}")
    if not ep.get("file"):
        errors.append(f"endpoint[{idx}] file is empty -- must be relative JS file path")
    if "/" not in str(ep.get("file", "")):
        errors.append(f"endpoint[{idx}] file '{ep.get('file')}' missing slash -- expected host/path/file.js format")
    if not ep.get("path"):
        errors.append(f"endpoint[{idx}] path is empty")
    if not isinstance(ep.get("line"), int):
        errors.append(f"endpoint[{idx}] line must be int, got {type(ep.get('line')).__name__} -- path={ep.get('path','?')}")
    return errors

def validate_taint(tp: dict, idx: int) -> list[str]:
    errors = []
    missing = REQUIRED_TAINT_FIELDS - set(tp.keys())
    if missing:
        errors.append(f"taint_path[{idx}] missing fields: {missing}")
    if tp.get("confidence") not in VALID_CONFIDENCE:
        errors.append(f"taint_path[{idx}] invalid confidence: {tp.get('confidence')}")
    if tp.get("estimated_bounty") not in VALID_BB_POTENTIAL:
        errors.append(f"taint_path[{idx}] invalid estimated_bounty: {tp.get('estimated_bounty')}")
    return errors

def validate_findings(findings: dict) -> list[str]:
    errors = []
    if "schema_version" not in findings:
        errors.append("schema_version field missing from findings.json")
    elif findings.get("schema_version") != 1:
        errors.append(f"schema_version must be 1, got: {findings.get('schema_version')}")
    if len(findings.get("endpoints", [])) > MAX_ENDPOINTS:
        errors.append(f"endpoints count {len(findings['endpoints'])} exceeds max {MAX_ENDPOINTS} — possible runaway extraction")
    if len(findings.get("taint_paths", [])) > MAX_TAINT_PATHS:
        errors.append(f"taint_paths count {len(findings['taint_paths'])} exceeds max {MAX_TAINT_PATHS} — possible hallucination loop")
    for i, ep in enumerate(findings.get("endpoints", [])):
        errors.extend(validate_endpoint(ep, i))
    for i, tp in enumerate(findings.get("taint_paths", [])):
        errors.extend(validate_taint(tp, i))
    return errors

BB_POTENTIAL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CATEGORY_ORDER = [
    "Auth & Identity", "Admin & Internal", "Data & Content",
    "File Upload / Export", "Billing & Payment",
    "Pub/Sub, Realtime & Promotions", "Integrations & Webhooks",
    "WebSocket", "GraphQL", "Uncategorized",
    "Base URLs & Environment Variables", "Client Routes", "Auth Signals"
]

def file_prefix(file_path: str) -> str:
    """
    Extracts the JS file identifier from a full relative path.
    e.g. "widget.sndcdn.com/widget-9.js" -> "widget.sndcdn.com/widget-9.js"
         "a-v2.sndcdn.com/assets/54.js"  -> "a-v2.sndcdn.com/assets/54.js"
    Returns the full relative path as-is — this IS the host+file context.
    The first segment (before /) is the serving host.
    """
    return file_path.strip() if file_path else "unknown"


def file_host(file_path: str) -> str:
    """Extracts just the serving host portion from a file path."""
    if not file_path or "/" not in file_path:
        return file_path or "unknown"
    return file_path.split("/")[0]


def merge_findings(base: dict, new: dict) -> dict:
    """
    Merge new_findings.json into base findings.json.
    Key: (method, host, path) for endpoints, id for taint/secrets.
    New entries overwrite old on key match. New-only entries are appended.
    Hunter-added fields (notes, manual_confirmed) are preserved from base.
    """
    merged = dict(base)

    # Endpoints — key by (method, host, path)
    base_ep_index = {
        (e["method"], e["path"], e.get("file", "")): i
        for i, e in enumerate(base.get("endpoints", []))
    }
    merged_eps = list(base.get("endpoints", []))
    new_count = 0
    updated_count = 0
    for ep in new.get("endpoints", []):
        key = (ep["method"], ep["path"], ep.get("file", ""))
        if key in base_ep_index:
            idx = base_ep_index[key]
            preserved = {k: v for k, v in merged_eps[idx].items() if k in ("notes", "manual_confirmed", "caido_validated")}
            merged_eps[idx] = {**ep, **preserved}
            updated_count += 1
        else:
            merged_eps.append(ep)
            new_count += 1
    merged["endpoints"] = merged_eps

    # Taint paths — key by id
    base_tp_index = {tp["id"]: i for i, tp in enumerate(base.get("taint_paths", []))}
    merged_tps = list(base.get("taint_paths", []))
    for tp in new.get("taint_paths", []):
        if tp["id"] in base_tp_index:
            idx = base_tp_index[tp["id"]]
            preserved = {k: v for k, v in merged_tps[idx].items() if k in ("notes", "manual_confirmed")}
            merged_tps[idx] = {**tp, **preserved}
        else:
            merged_tps.append(tp)
    merged["taint_paths"] = merged_tps

    # Secrets — key by (type, file, line)
    base_sec_index = {
        (s["type"], s["file"], s["line"]): i
        for i, s in enumerate(base.get("secrets", []))
    }
    merged_secs = list(base.get("secrets", []))
    for sec in new.get("secrets", []):
        key = (sec["type"], sec["file"], sec["line"])
        if key not in base_sec_index:
            merged_secs.append(sec)
    merged["secrets"] = merged_secs

    merged["meta"]["last_merged"] = datetime.utcnow().isoformat()
    merged["meta"]["merge_stats"] = {
        "endpoints_new": new_count,
        "endpoints_updated": updated_count
    }
    return merged

# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_endpoints(findings: dict, host_map: dict = None) -> str:
    endpoints = findings.get("endpoints", [])
    if not endpoints:
        return "# Endpoints\n\nNo endpoints extracted.\n"

    # Sort by bb_potential then file then path
    endpoints = sorted(endpoints, key=lambda e: (
        BB_POTENTIAL_ORDER.get(e.get("bb_potential", "INFO"), 99),
        e.get("file", ""),
        e.get("path", "")
    ))

    lines = ["# Endpoints\n"]

    # --- Top 10 ---
    server_eps = [e for e in endpoints if e.get("ep_type", "server") == "server"]
    top10 = sorted(server_eps, key=lambda e: (
        BB_POTENTIAL_ORDER.get(e.get("bb_potential", "INFO"), 99),
        0 if e.get("single_request_test") else 1,
        e.get("file", ""),
        e.get("path", "")
    ))[:10]

    lines.append("## Top 10 Priority Endpoints\n")
    lines.append("> Ranked by BB Potential × Testability. File column shows the exact JS source.\n")
    lines.append("| Rank | File | Endpoint | BB Potential | First Test | Line |")
    lines.append("|------|------|----------|-------------|------------|------|")
    for i, ep in enumerate(top10, 1):
        lines.append(
            f"| {i} | {ep.get('file','?')} | "
            f"`{ep.get('method','?')} {ep.get('path','?')}` | "
            f"{ep.get('bb_potential','?')} | {ep.get('first_test','?')} | {ep.get('line','?')} |"
        )
    lines.append("")

    # --- Summary ---
    flag_counts: dict[str, int] = {}
    for ep in server_eps:
        for f in ep.get("flags", []):
            flag_counts[f] = flag_counts.get(f, 0) + 1
    client_eps = [e for e in endpoints if e.get("ep_type") == "client_route"]
    ws_eps = [e for e in endpoints if "WEBSOCKET" in e.get("flags", [])]
    gql_eps = [e for e in endpoints if "GRAPHQL" in e.get("flags", [])]

    lines.append("## Summary\n")
    lines.append(f"- Total server API endpoints: {len(server_eps)}")
    lines.append(f"- Total client routes: {len(client_eps)}")
    flag_str = " | ".join(f"{k}={v}" for k, v in sorted(flag_counts.items()))
    lines.append(f"- Flagged: {flag_str or 'none'}")
    lines.append(f"- WebSocket endpoints: {len(ws_eps)}")
    lines.append(f"- GraphQL: {'detected' if gql_eps else 'not detected'}")
    lines.append("")

    # --- JS Files in Scope ---
    # Group by serving host (first path segment) for the overview table
    # then show per-file breakdown
    host_stats: dict[str, dict] = {}
    file_stats: dict[str, dict] = {}
    for ep in server_eps:
        f = ep.get("file", "unknown")
        h = file_host(f)
        # Per-host stats
        if h not in host_stats:
            host_stats[h] = {"count": 0, "flags": {}, "files": set()}
        host_stats[h]["count"] += 1
        host_stats[h]["files"].add(f)
        for flag in ep.get("flags", []):
            host_stats[h]["flags"][flag] = host_stats[h]["flags"].get(flag, 0) + 1
        # Per-file stats
        if f not in file_stats:
            file_stats[f] = {"count": 0, "flags": {}}
        file_stats[f]["count"] += 1
        for flag in ep.get("flags", []):
            file_stats[f]["flags"][flag] = file_stats[f]["flags"].get(flag, 0) + 1

    lines.append("## JS Files in Scope\n")
    lines.append("> Grouped by serving host. Each file row shows which JS file the endpoints were extracted from.")
    lines.append("> Since you downloaded these files in Caido, the file path is the definitive host attribution.\n")

    for host in sorted(host_stats.keys(), key=lambda h: -host_stats[h]["count"]):
        hdata = host_stats[host]
        host_flags = ", ".join(f"{k}={v}" for k, v in sorted(hdata["flags"].items(), key=lambda x: -x[1]))
        lines.append(f"### {host} — {hdata['count']} endpoints\n")
        lines.append("| JS File | Endpoints | Flags |")
        lines.append("|---------|-----------|-------|")
        for fpath in sorted(hdata["files"], key=lambda fp: -file_stats[fp]["count"]):
            fdata = file_stats[fpath]
            fflags = ", ".join(f"{k}={v}" for k, v in sorted(fdata["flags"].items(), key=lambda x: -x[1]))
            lines.append(f"| `{fpath}` | {fdata['count']} | {fflags or '—'} |")
        lines.append("")

    # --- Category tables ---
    # Build categories from server_eps, but GraphQL section is special:
    # pull all ep_type=="graphql" entries regardless of their category field
    # so GraphQL endpoints categorized under Billing/Data still appear in the GraphQL section
    gql_all = [e for e in endpoints if e.get("ep_type") == "graphql"]
    categories: dict[str, list] = {}
    for ep in server_eps:
        # Don't double-count graphql endpoints in their business-function category
        if ep.get("ep_type") == "graphql":
            continue
        cat = ep.get("category", "Uncategorized")
        categories.setdefault(cat, []).append(ep)
    # GraphQL section gets ALL graphql ep_type entries
    if gql_all:
        categories["GraphQL"] = gql_all

    for cat in CATEGORY_ORDER:
        eps = categories.get(cat, [])
        if not eps:
            continue
        eps = sorted(eps, key=lambda e: (
            BB_POTENTIAL_ORDER.get(e.get("bb_potential", "INFO"), 99),
            e.get("file", ""),
            e.get("path", "")
        ))
        lines.append(f"## {cat}\n")
        lines.append("| Method | Path | File | Line | Flags | BB Potential | Prior Art | First Test |")
        lines.append("|--------|------|------|------|-------|-------------|-----------|------------|")
        for ep in eps:
            flags = ", ".join(ep.get("flags", [])) or "—"
            prior_art = ep.get("prior_art", "UNKNOWN")
            lines.append(
                f"| {ep.get('method','?')} | `{ep.get('path','?')}` | "
                f"{ep.get('file','?')} | {ep.get('line','?')} | "
                f"{flags} | {ep.get('bb_potential','?')} | {prior_art} | {ep.get('first_test','?')} |"
            )
        lines.append("")

    # --- Client routes ---
    if client_eps:
        client_eps = sorted(client_eps, key=lambda e: (e.get("file", ""), e.get("path", "")))
        lines.append("## Client Routes\n")
        lines.append("| Path | File | Line | Notes |")
        lines.append("|------|------|------|-------|")
        for ep in client_eps:
            lines.append(f"| `{ep.get('path','?')}` | {ep.get('file','?')} | {ep.get('line','?')} | {ep.get('notes','—')} |")
        lines.append("")

    # --- Auth Signals ---
    auth_signals = findings.get("auth_signals", {})
    if auth_signals:
        lines.append("## Auth Signals\n")
        for section, rows in auth_signals.items():
            if not rows:
                continue
            lines.append(f"### {section}\n")
            if section == "Token Storage":
                lines.append("| Token Key | Storage | File | Line | Risk |")
                lines.append("|-----------|---------|------|------|------|")
                for r in rows:
                    lines.append(f"| {r.get('key','—')} | {r.get('storage','—')} | {r.get('file','—')} | {r.get('line','—')} | {r.get('risk','—')} |")
            elif section == "OAuth / OIDC Signals":
                lines.append("| Pattern | File | Line | Notes |")
                lines.append("|---------|------|------|-------|")
                for r in rows:
                    lines.append(f"| {r.get('pattern','—')} | {r.get('file','—')} | {r.get('line','—')} | {r.get('notes','—')} |")
            elif section == "Client-Side Role Checks":
                lines.append("> Every row here is a potential bypass — server must enforce the same check.\n")
                lines.append("| Check | File | Line |")
                lines.append("|-------|------|------|")
                for r in rows:
                    lines.append(f"| {r.get('check','—')} | {r.get('file','—')} | {r.get('line','—')} |")
            else:
                lines.append("| Pattern | File | Line | Risk |")
                lines.append("|---------|------|------|------|")
                for r in rows:
                    lines.append(f"| {r.get('pattern', r.get('check', '—'))} | {r.get('file','—')} | {r.get('line','—')} | {r.get('risk','—')} |")
            lines.append("")

    # --- Evidence Gaps ---
    gaps = findings.get("evidence_gaps", [])
    if gaps:
        lines.append("## Evidence Gaps\n")
        for g in gaps:
            lines.append(f"- [ ] {g}")
        lines.append("")

    return "\n".join(lines)


def render_taint(findings: dict, host_map: dict = None) -> str:
    taint_paths = findings.get("taint_paths", [])
    if not taint_paths:
        return "# Taint Analysis\n\nNo taint paths found.\n"

    lines = ["# Taint Analysis\n"]

    # --- Top Findings ---
    confirmed = [tp for tp in taint_paths if tp["confidence"] == "CONFIRMED"]
    inferred = [tp for tp in taint_paths if tp["confidence"] == "INFERRED"]
    top = sorted(confirmed + inferred,
                 key=lambda t: (BB_POTENTIAL_ORDER.get(t["estimated_bounty"], 99), t["id"]))

    lines.append("## Top Findings\n")
    lines.append("> Ranked by hunter value. Synthesis builds chains from this section first.\n")
    lines.append("| Rank | Finding | Confidence | Estimated Bounty | File | Line |")
    lines.append("|------|---------|------------|-----------------|------|------|")
    for i, tp in enumerate(top, 1):
        summary = tp.get("summary", f"{tp['source_type']} → {tp['sink_type']}")
        lines.append(f"| {i} | {summary} | {tp['confidence']} | {tp['estimated_bounty']} | {tp['source_file']} | {tp['source_line']} |")
    lines.append("")

    # --- Summary ---
    sources = findings.get("sources", [])
    sinks = findings.get("sinks", [])
    pm_handlers = findings.get("postmessage_handlers", [])
    weak_origins = [h for h in pm_handlers if h.get("origin_check") == "NONE"]
    proto_candidates = findings.get("prototype_pollution", [])

    lines.append("## Summary\n")
    lines.append(f"- Sources found: {len(sources)}")
    lines.append(f"- Sinks found: {len(sinks)}")
    lines.append(f"- Confirmed taint paths: {len(confirmed)}")
    lines.append(f"- Inferred taint paths: {len(inferred)}")
    lines.append(f"- postMessage handlers: {len(pm_handlers)} (weak origin checks: {len(weak_origins)})")
    lines.append(f"- Prototype pollution candidates: {len(proto_candidates)}")
    lines.append("")

    # --- Sources ---
    if sources:
        lines.append("## Sources\n")
        lines.append("| Type | Pattern | File | Line |")
        lines.append("|------|---------|------|------|")
        for s in sources:
            lines.append(f"| {s.get('type','—')} | `{s.get('pattern','—')}` | {s.get('file','—')} | {s.get('line','—')} |")
        lines.append("")

    # --- Sinks ---
    if sinks:
        lines.append("## Sinks\n")
        lines.append("| Type | Pattern | File | Line |")
        lines.append("|------|---------|------|------|")
        for s in sinks:
            lines.append(f"| {s.get('type','—')} | `{s.get('pattern','—')}` | {s.get('file','—')} | {s.get('line','—')} |")
        lines.append("")

    # --- Taint Paths ---
    if taint_paths:
        lines.append("## Taint Paths\n")
        for tp in top:
            lines.append(f"### {tp['id']}: {tp.get('summary', tp['source_type'] + ' → ' + tp['sink_type'])}\n")
            hops = tp.get("hops", [])
            if hops:
                lines.append("| Hop | Operation | File | Line | Status |")
                lines.append("|-----|-----------|------|------|--------|")
                for hop in hops:
                    lines.append(f"| {hop.get('hop','—')} | {hop.get('operation','—')} | {hop.get('file','—')} | {hop.get('line','—')} | {hop.get('status','—')} |")
                lines.append("")
            lines.append(f"Sanitizer: {tp.get('sanitizer', 'None')}")
            lines.append(f"Confidence: {tp['confidence']}")
            lines.append(f"Risk: {tp.get('risk_description', '—')}")
            lines.append("")
            mt = tp.get("manual_test", "")
            if mt:
                lines.append("**Manual test:**")
                lines.append("```")
                lines.append(mt)
                lines.append("```")
                lines.append("")
            lines.append(f"Submission Ready: {tp.get('submission_ready', 'NO')} — needs: {tp.get('submission_blocker', 'see risk description')}")
            lines.append(f"Estimated Bounty: {tp['estimated_bounty']}")
            lines.append(f"Prior Art: {tp.get('prior_art', 'UNKNOWN')}")
            lines.append("")
            dt = tp.get("debugger_trace")
            if dt and tp.get("confidence") in ("CONFIRMED", "INFERRED"):
                steps = dt.get("steps", [])
                if steps:
                    lines.append("**Debugger trace:**")
                    lines.append("")
                    for i, step in enumerate(steps, 1):
                        lines.append(f"{i}. {step}")
                    lines.append("")
                trigger = dt.get("trigger_action", "")
                exploit = dt.get("exploitation_step", "")
                if trigger:
                    lines.append(f"Trigger: `{trigger}`")
                if exploit:
                    lines.append(f"Exploitation: `{exploit}`")
                lines.append("")
            lines.append("\n---\n")

    # --- postMessage ---
    if pm_handlers:
        lines.append("## postMessage Handlers\n")
        lines.append("| File | Line | Origin Check | Risk |")
        lines.append("|------|------|-------------|------|")
        for h in pm_handlers:
            lines.append(f"| {h.get('file','—')} | {h.get('line','—')} | {h.get('origin_check','—')} | {h.get('risk','—')} |")
        lines.append("")

    # --- CSRF ---
    csrf = findings.get("csrf_analysis", {})
    if csrf:
        lines.append("## CSRF Analysis\n")
        mitigations = csrf.get("mitigations", [])
        if mitigations:
            lines.append("### Mitigations Found\n")
            lines.append("| Mitigation | Where Applied | File | Line |")
            lines.append("|------------|---------------|------|------|")
            for m in mitigations:
                lines.append(f"| {m.get('type','—')} | {m.get('where','—')} | {m.get('file','—')} | {m.get('line','—')} |")
            lines.append("")
        ep_risks = csrf.get("endpoint_risks", [])
        if ep_risks:
            lines.append("### Endpoint Risk\n")
            lines.append("| Endpoint | Method | Auth Type | CSRF Protection | Risk |")
            lines.append("|----------|--------|-----------|-----------------|------|")
            for r in ep_risks:
                lines.append(f"| `{r.get('endpoint','—')}` | {r.get('method','—')} | {r.get('auth_type','—')} | {r.get('csrf_protection','None')} | {r.get('risk','—')} |")
            lines.append("")

    # --- Prototype Pollution ---
    if proto_candidates:
        lines.append("## Prototype Pollution Candidates\n")
        lines.append("| Merge Function | User Input Source | File | Line | Test Payload |")
        lines.append("|----------------|-------------------|------|------|--------------|")
        for p in proto_candidates:
            lines.append(f"| {p.get('function','—')} | {p.get('input_source','—')} | {p.get('file','—')} | {p.get('line','—')} | `{p.get('test_payload','—')}` |")
        lines.append("")

    # --- Service Workers ---
    sw = findings.get("service_workers", [])
    if sw:
        lines.append("## Service Workers\n")
        for w in sw:
            lines.append(f"### {w.get('file','unknown')}\n")
            lines.append(f"- importScripts versioned: {w.get('versioned_imports', 'unknown')}")
            lines.append(f"- Risk: {w.get('risk','—')}")
            lines.append("")

    # --- Sanitizers ---
    sc = findings.get("security_components", {})
    if sc:
        lines.append("## Security Components\n")
        dp = sc.get("dompurify", {})
        if dp.get("present"):
            cve_str = ", ".join(dp.get("cves", [])) or "none"
            overrides = ", ".join(dp.get("config_overrides", [])) or "none"
            lines.append(f"**DOMPurify** v{dp.get('version','UNKNOWN')} — CVE risk: `{dp.get('cve_risk','UNKNOWN')}` — CVEs: {cve_str}")
            lines.append(f"Config overrides: {overrides}")
            if dp.get("notes"):
                lines.append(f"Notes: {dp['notes']}")
            lines.append("")
        else:
            lines.append("**DOMPurify:** not detected — all innerHTML/dangerouslySetInnerHTML sinks are unmitigated")
            lines.append("")
        for s in sc.get("other_sanitizers", []):
            lines.append(f"**{s.get('name','?')}** — {s.get('file','?')}:{s.get('line','?')} — {s.get('notes','')}")
        filters = sc.get("hardcoded_filters", [])
        if filters:
            lines.append("")
            lines.append(f"**Hardcoded filters:** {len(filters)}")
            lines.append("| Type | Scope | Case sensitive | Action | Bypass notes |")
            lines.append("|------|-------|---------------|--------|-------------|")
            for f in filters:
                lines.append(f"| {f.get('type','?')} | {f.get('scope','?')} | {f.get('case_sensitive','?')} | {f.get('action','?')} | {f.get('bypass_notes','—')} |")
        if sc.get("trusted_types"):
            lines.append("")
            lines.append("**Trusted Types:** enforced — XSS requires policy bypass")
        lines.append("")
    elif findings.get("sanitizers"):
        # Legacy fallback
        sanitizers = findings["sanitizers"]
        lines.append("## Sanitizers\n")
        lines.append("| Sanitizer | File | Line | Effectiveness | Bypass Risk |")
        lines.append("|-----------|------|------|--------------|-------------|")
        for s in sanitizers:
            lines.append(f"| {s.get('name','—')} | {s.get('file','—')} | {s.get('line','—')} | {s.get('effectiveness','—')} | {s.get('bypass_risk','—')} |")
        lines.append("")

    return "\n".join(lines)


def render_secrets(findings: dict, host_map: dict = None) -> str:
    secrets = findings.get("secrets", [])
    if not secrets:
        return "# Secrets\n\nNo secrets found.\n"

    lines = ["# Secrets\n"]
    confirmed = [s for s in secrets if s.get("confirmed")]
    unconfirmed = [s for s in secrets if not s.get("confirmed")]

    if confirmed:
        lines.append("## Confirmed Secrets\n")
        lines.append("| Type | Value (redacted) | File | Line | Risk |")
        lines.append("|------|-----------------|------|------|------|")
        for s in confirmed:
            lines.append(f"| {s['type']} | `{s['value_redacted']}` | {s['file']} | {s['line']} | {s.get('risk','HIGH')} |")
        lines.append("")

    if unconfirmed:
        lines.append("## Candidates (unconfirmed)\n")
        lines.append("| Type | Value (redacted) | File | Line | False Positive Risk |")
        lines.append("|------|-----------------|------|------|---------------------|")
        for s in unconfirmed:
            lines.append(f"| {s['type']} | `{s['value_redacted']}` | {s['file']} | {s['line']} | {s.get('fp_risk','MEDIUM')} |")
        lines.append("")

    staging_urls = findings.get("staging_urls", [])
    if staging_urls:
        lines.append("## Staging & Internal URLs\n")
        lines.append("| URL | File | Line | Notes |")
        lines.append("|-----|------|------|-------|")
        for u in staging_urls:
            lines.append(f"| `{u.get('url','—')}` | {u.get('file','—')} | {u.get('line','—')} | {u.get('notes','—')} |")
        lines.append("")

    env_refs = findings.get("env_references", [])
    if env_refs:
        lines.append("## Environment References\n")
        lines.append("| Variable | File | Line |")
        lines.append("|----------|------|------|")
        for r in env_refs:
            lines.append(f"| `{r.get('variable','—')}` | {r.get('file','—')} | {r.get('line','—')} |")
        lines.append("")

    return "\n".join(lines)


def render_bbcontext(findings: dict, host_map: dict = None) -> str:
    ctx = findings.get("bb_context", {})
    if not ctx:
        return "# Bug Bounty Context\n\nNo context available — Phase 0 did not run or target has no program.\n"

    lines = ["# Bug Bounty Context\n"]

    # Program info
    lines.append("## Program Info\n")
    lines.append(f"- Platform: {ctx.get('platform', 'UNKNOWN')}")
    lines.append(f"- Program: {ctx.get('program_name', 'UNKNOWN')}")
    if ctx.get('program_url'):
        lines.append(f"- URL: {ctx.get('program_url')}")
    lines.append(f"- Type: {ctx.get('program_type', 'UNKNOWN')}")
    lines.append(f"- Offers bounties: {ctx.get('offers_bounties', 'UNKNOWN')}")
    lines.append("")

    # Prior art map
    prior_art = ctx.get("prior_art_map", [])
    if prior_art:
        lines.append("## Prior Art Map\n")
        lines.append("| Vuln Class | Report Count | Dupe Risk |")
        lines.append("|------------|--------------|-----------|")
        for row in prior_art:
            lines.append(f"| {row.get('vuln_class','—')} | {row.get('report_count','—')} | {row.get('dupe_risk','—')} |")
        lines.append("")
    else:
        lines.append("## Prior Art Map\n")
        lines.append("No prior art data available — all dupe risk UNKNOWN.\n")

    # Out-of-scope vuln classes (new field name)
    exclusions = ctx.get("out_of_scope_vuln_classes", ctx.get("out_of_scope", []))
    if exclusions:
        lines.append("## Out-of-Scope Vuln Classes\n")
        for ex in exclusions:
            lines.append(f"- {ex}")
        lines.append("")

    # Kill list seeds
    kill_seeds = ctx.get("kill_list_seeds", [])
    if kill_seeds:
        lines.append("## Kill List Seeds\n")
        lines.append("| Item | Reason |")
        lines.append("|------|--------|")
        for k in kill_seeds:
            lines.append(f"| {k.get('item','—')} | {k.get('reason','—')} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Deterministic bug bounty report renderer")
    parser.add_argument("--findings", required=True, help="Path to findings.json")
    parser.add_argument("--host-map", required=False, default=None, help="Path to host_map.json (optional — file paths are now the source of truth)")
    parser.add_argument("--output-dir", required=True, help="Output directory for markdown files")
    parser.add_argument("--merge", help="Path to new_findings.json to merge before rendering")
    parser.add_argument("--only", choices=["endpoints", "taint", "secrets", "bbcontext", "all"], default="all")
    parser.add_argument("--validate-only", action="store_true", help="Validate schema and exit without rendering")
    args = parser.parse_args()

    # Load findings
    if not os.path.exists(args.findings):
        print(f"ERROR: findings.json not found: {args.findings}", file=sys.stderr)
        sys.exit(1)
    with open(args.findings) as f:
        findings = json.load(f)

    # Load host map — now optional since file paths are the source of truth
    host_map = {}
    if args.host_map and os.path.exists(args.host_map):
        with open(args.host_map) as f:
            host_map = json.load(f)

    # Merge if requested
    if args.merge:
        if not os.path.exists(args.merge):
            print(f"ERROR: merge file not found: {args.merge}", file=sys.stderr)
            sys.exit(1)
        with open(args.merge) as f:
            new_findings = json.load(f)
        findings = merge_findings(findings, new_findings)
        # Write merged findings back
        with open(args.findings, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"Merged findings written to {args.findings}")
        stats = findings["meta"].get("merge_stats", {})
        print(f"  New endpoints: {stats.get('endpoints_new', 0)}")
        print(f"  Updated endpoints: {stats.get('endpoints_updated', 0)}")

    # Validate schema
    errors = validate_findings(findings)
    if errors:
        print(f"SCHEMA VALIDATION ERRORS ({len(errors)}):", file=sys.stderr)
        for e in errors[:20]:
            print(f"  {e}", file=sys.stderr)
        if len(errors) > 20:
            print(f"  ... and {len(errors)-20} more", file=sys.stderr)
        if args.validate_only or len(errors) > 50:
            print("Aborting — too many schema errors. Fix findings.json before rendering.", file=sys.stderr)
            sys.exit(1)
        print(f"Continuing with {len(errors)} warnings...", file=sys.stderr)

    if args.validate_only:
        if errors:
            print(f"VALIDATION FAILED: {len(errors)} error(s). Fix findings.json before rendering.", file=sys.stderr)
            sys.exit(1)
        print("Validation passed.")
        sys.exit(0)

    os.makedirs(args.output_dir, exist_ok=True)

    renders = {
        "endpoints": ("Endpoints.md", lambda: render_endpoints(findings, host_map)),
        "taint": ("Taint.md", lambda: render_taint(findings, host_map)),
        "secrets": ("Secrets.md", lambda: render_secrets(findings)),
        "bbcontext": ("BBContext.md", lambda: render_bbcontext(findings)),
    }

    to_render = list(renders.keys()) if args.only == "all" else [args.only]

    for key in to_render:
        filename, render_fn = renders[key]
        out_path = os.path.join(args.output_dir, filename)
        content = render_fn()
        with open(out_path, "w") as f:
            f.write(content)
        size = os.path.getsize(out_path)
        print(f"Wrote {filename}: {size} bytes")

    print("Done.")

if __name__ == "__main__":
    main()
