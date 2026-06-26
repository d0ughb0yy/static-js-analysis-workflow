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
REQUIRED_SECRET_FIELDS = {"type", "file", "line", "value_redacted", "confirmed"}
VALID_BB_POTENTIAL = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_FLAGS = {"IDOR", "ADMIN", "UPLOAD", "REDIRECT", "AUTH", "EXPORT", "WEBSOCKET", "GRAPHQL", "CORS"}
VALID_CATEGORIES = {
    "Auth & Identity", "Admin & Internal", "Data & Content",
    "File Upload / Export", "Billing & Payment",
    "Pub/Sub, Realtime & Promotions", "Integrations & Webhooks",
    "WebSocket", "GraphQL", "Uncategorized",
    "Base URLs & Environment Variables", "Client Routes",
}
VALID_EP_TYPES = {"server", "client_route", "websocket", "graphql"}
MAX_ENDPOINTS = 2000

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

def validate_findings(findings: dict) -> list[str]:
    errors = []
    if "schema_version" not in findings:
        errors.append("schema_version field missing from findings.json")
    elif findings.get("schema_version") != 1:
        errors.append(f"schema_version must be 1, got: {findings.get('schema_version')}")
    if len(findings.get("endpoints", [])) > MAX_ENDPOINTS:
        errors.append(f"endpoints count {len(findings['endpoints'])} exceeds max {MAX_ENDPOINTS} — possible runaway extraction")
    for i, ep in enumerate(findings.get("endpoints", [])):
        errors.extend(validate_endpoint(ep, i))
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


def md_cell(value) -> str:
    """
    Escapes a value for safe use inside a markdown table cell.

    A literal `|` in any field — most commonly a raw regex pattern like
    `(html|append|prepend|replaceWith)` ending up in a 'pattern' field instead
    of the actual matched source text — gets interpreted by markdown table
    parsers (including Obsidian) as an extra column delimiter. This silently
    corrupts that row's column count, and most renderers then pad every other
    row in the table to match the widest row, producing garbled tables with
    empty trailing columns across the entire table, not just the offending row.

    Also collapses embedded newlines, which would otherwise break out of the
    cell entirely and corrupt the table in a different way.
    """
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return s


def merge_findings(base: dict, new: dict) -> dict:
    """
    Merge new_findings.json into base findings.json.
    Key: (method, host, path) for endpoints.
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
        return "No endpoints extracted.\n"

    program_intel = findings.get("meta", {}).get("program_intel", {})
    out_of_scope_hosts = set(program_intel.get("out_of_scope_hosts", []) or [])

    def is_out_of_scope(ep: dict) -> bool:
        return file_host(ep.get("file", "")) in out_of_scope_hosts

    # Sort by bb_potential then file then path
    endpoints = sorted(endpoints, key=lambda e: (
        BB_POTENTIAL_ORDER.get(e.get("bb_potential", "INFO"), 99),
        e.get("file", ""),
        e.get("path", "")
    ))

    lines = []

    # --- IDOR Clusters ---
    idor_clusters = findings.get("idor_clusters", [])
    visible_clusters = [
        c for c in idor_clusters
        if c.get("has_viable_primary") and c.get("host", "") not in out_of_scope_hosts
    ]
    if visible_clusters:
        lines.append("## IDOR Clusters\n")
        lines.append("| File | Test This | Methods | ID Type | Endpoints | Priority |")
        lines.append("|------|-----------|---------|---------|-----------|----------|")
        for c in visible_clusters:
            primaries = ", ".join(f"`{p}`" for p in c.get("viable_primaries", []))
            lines.append(
                f"| {md_cell(c.get('host','?') + c.get('prefix',''))} | {primaries} | "
                f"{md_cell(', '.join(c.get('methods', [])))} | {md_cell(c.get('id_type','?'))} | "
                f"{c.get('endpoint_count','?')} | {md_cell(c.get('max_potential','?'))} |"
            )
        lines.append("")

    # --- Top 10 ---
    server_eps = [e for e in endpoints if e.get("ep_type", "server") == "server"]
    top10_candidates = [e for e in server_eps if not is_out_of_scope(e)]
    top10 = sorted(top10_candidates, key=lambda e: (
        BB_POTENTIAL_ORDER.get(e.get("bb_potential", "INFO"), 99),
        0 if e.get("single_request_test") else 1,
        e.get("file", ""),
        e.get("path", "")
    ))[:10]

    if top10:
        lines.append("## Top 10\n")
        lines.append("| Rank | Endpoint | First Test | File | Line |")
        lines.append("|------|----------|------------|------|------|")
        for i, ep in enumerate(top10, 1):
            oos = "⛔ OUT OF SCOPE — " if is_out_of_scope(ep) else ""
            lines.append(
                f"| {i} | `{md_cell(ep.get('method','?'))} {md_cell(ep.get('path','?'))}` | "
                f"{oos}{md_cell(ep.get('first_test','?'))} | "
                f"{md_cell(ep.get('file','?'))} | {ep.get('line','?')} |"
            )
        lines.append("")

    # --- Category tables ---
    gql_all = [e for e in endpoints if e.get("ep_type") == "graphql"]
    categories: dict[str, list] = {}
    for ep in server_eps:
        if ep.get("ep_type") == "graphql":
            continue
        cat = ep.get("category", "Uncategorized")
        categories.setdefault(cat, []).append(ep)
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
        lines.append("| Method | Endpoint | File | First Test | Line | Flag |")
        lines.append("|--------|----------|------|------------|------|------|")
        for ep in eps:
            flags = ", ".join(ep.get("flags", [])) or "—"
            first_test = ep.get("first_test", "?")
            if is_out_of_scope(ep):
                first_test = f"⛔ OUT OF SCOPE — {first_test}"
            lines.append(
                f"| {md_cell(ep.get('method','?'))} | `{md_cell(ep.get('path','?'))}` | "
                f"{md_cell(ep.get('file','?'))} | {md_cell(first_test)} | "
                f"{ep.get('line','?')} | {md_cell(flags)} |"
            )
        lines.append("")

    # --- Client Routes ---
    client_eps = [e for e in endpoints if e.get("ep_type") == "client_route"]
    if client_eps:
        client_eps = sorted(client_eps, key=lambda e: (e.get("file", ""), e.get("path", "")))
        lines.append("## Client Routes\n")
        lines.append("| Path | File | Line | Notes |")
        lines.append("|------|------|------|-------|")
        for ep in client_eps:
            lines.append(f"| `{md_cell(ep.get('path','?'))}` | {md_cell(ep.get('file','?'))} | {ep.get('line','?')} | {md_cell(ep.get('notes','—'))} |")
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
                    lines.append(f"| {md_cell(r.get('key','—'))} | {md_cell(r.get('storage','—'))} | {md_cell(r.get('file','—'))} | {r.get('line','—')} | {md_cell(r.get('risk','—'))} |")
            elif section == "OAuth / OIDC Signals":
                lines.append("| Pattern | File | Line | Notes |")
                lines.append("|---------|------|------|-------|")
                for r in rows:
                    lines.append(f"| {md_cell(r.get('pattern','—'))} | {md_cell(r.get('file','—'))} | {r.get('line','—')} | {md_cell(r.get('notes','—'))} |")
            elif section == "Client-Side Role Checks":
                lines.append("> Every row here is a potential bypass — server must enforce the same check.\n")
                lines.append("| Check | File | Line |")
                lines.append("|-------|------|------|")
                for r in rows:
                    lines.append(f"| {md_cell(r.get('check','—'))} | {md_cell(r.get('file','—'))} | {r.get('line','—')} |")
            else:
                lines.append("| Pattern | File | Line | Risk |")
                lines.append("|---------|------|------|------|")
                for r in rows:
                    lines.append(f"| {md_cell(r.get('pattern', r.get('check', '—')))} | {md_cell(r.get('file','—'))} | {r.get('line','—')} | {md_cell(r.get('risk','—'))} |")
            lines.append("")

    # --- Evidence Gaps ---
    gaps = findings.get("evidence_gaps", [])
    if gaps:
        lines.append("## Evidence Gaps\n")
        for g in gaps:
            lines.append(f"- [ ] {g}")
        lines.append("")

    return "\n".join(lines)


def render_secrets(findings: dict, host_map: dict = None) -> str:
    secrets = findings.get("secrets", [])
    staging_urls = findings.get("staging_urls", [])
    env_refs = findings.get("env_references", [])

    if not any([secrets, staging_urls, env_refs]):
        return "No secrets found.\n"

    lines = []
    confirmed = [s for s in secrets if s.get("confirmed")]
    unconfirmed = [s for s in secrets if not s.get("confirmed")]

    if confirmed:
        lines.append("## Confirmed Secrets\n")
        lines.append("| Type | Value (redacted) | File | Line | Risk |")
        lines.append("|------|-----------------|------|------|------|")
        for s in confirmed:
            lines.append(f"| {md_cell(s['type'])} | `{md_cell(s['value_redacted'])}` | {md_cell(s['file'])} | {s['line']} | {md_cell(s.get('risk','HIGH'))} |")
        lines.append("")

    if unconfirmed:
        lines.append("## Candidates (unconfirmed)\n")
        lines.append("| Type | Value (redacted) | File | Line | False Positive Risk |")
        lines.append("|------|-----------------|------|------|---------------------|")
        for s in unconfirmed:
            lines.append(f"| {md_cell(s['type'])} | `{md_cell(s['value_redacted'])}` | {md_cell(s['file'])} | {s['line']} | {md_cell(s.get('fp_risk','MEDIUM'))} |")
        lines.append("")

    if staging_urls:
        lines.append("## Staging & Internal URLs\n")
        lines.append("| URL | File | Line | Notes |")
        lines.append("|-----|------|------|-------|")
        for u in staging_urls:
            lines.append(f"| `{md_cell(u.get('url','—'))}` | {md_cell(u.get('file','—'))} | {u.get('line','—')} | {md_cell(u.get('notes','—'))} |")
        lines.append("")

    if env_refs:
        lines.append("## Environment References\n")
        lines.append("| Variable | File | Line |")
        lines.append("|----------|------|------|")
        for r in env_refs:
            var_name = r.get('variable', r.get('var', '—'))
            lines.append(f"| `{md_cell(var_name)}` | {md_cell(r.get('file','—'))} | {r.get('line','—')} |")
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
    parser.add_argument("--only", choices=["endpoints", "secrets", "all"], default="all")
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
        "secrets": ("Secrets.md", lambda: render_secrets(findings)),
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
