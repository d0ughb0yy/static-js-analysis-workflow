---
name: decode-sourcemaps
description: Extract original JavaScript source trees from source map files using the sourcemapper binary. Handles .js.map files, inline data: sourcemap references, and JS files with embedded sourcemap URLs.
license: MIT
compatibility: opencode
metadata:
  category: security
  domain: static-analysis
  language: javascript
---

## What I do

I use the `sourcemapper` binary (https://github.com/denandz/sourcemapper) to recover original source trees from webpack/bundler source maps. This is essential for static analysis because minified bundles have mangled names and collapsed whitespace — sourcemapper reconstructs the original file tree with real function names, comments, and module boundaries.

Handles three input types:
- `.js.map` files on disk (pass the file path as `-url`)
- `.map` URLs (pass the URL as `-url`)
- JS files with an embedded `sourceMappingURL` comment — including inline `data:` base64 blobs — (pass the JS URL or path as `-jsurl`)

## Prerequisites

`sourcemapper` must be installed on the host machine:

```bash
go install github.com/denandz/sourcemapper@latest
```

Verify before running:

```bash
which sourcemapper || echo "NOT INSTALLED"
sourcemapper -help 2>&1 | head -5
```

If not installed, skip decoding and note it — Phase 2 and Phase 3 will run on the minified bundles only (still functional, just lower signal quality).

## Usage

### From local .js.map files (most common case)

```bash
find "<js_dir>" -type f -name "*.js.map" | sort
```

For each `.js.map` found, run:

```bash
sourcemapper -url "<js_dir>/<name>.js.map" -output "<js_dir>/decoded-sources/<name>"
```

Example batch run for all maps in a directory:

```bash
cat > /tmp/sm_decode.sh << 'SHEOF'
#!/bin/bash
JS_DIR="<js_dir>"
OUT_BASE="$JS_DIR/decoded-sources"
mkdir -p "$OUT_BASE"
find "$JS_DIR" -maxdepth 3 -name "*.js.map" | while read mapfile; do
    relpath="${mapfile#$JS_DIR/}"
    outname="${relpath//\//_}"
    outname="${outname%.js.map}"
    outdir="$OUT_BASE/$outname"
    echo "[+] $relpath -> $outdir"
    sourcemapper -url "$mapfile" -output "$outdir" 2>&1 | tail -3
done
SHEOF
bash /tmp/sm_decode.sh
```

### From a JS file with embedded sourcemap reference

When a `.js.map` file is not on disk but the JS file has a `sourceMappingURL` comment pointing to a URL or contains an inline `data:` blob:

```bash
sourcemapper -jsurl "https://example.com/assets/app.js" -output "<js_dir>/decoded-sources/app"
```

Add `-header "Cookie: session=..."` or `-header "Authorization: Bearer ..."` if the target requires authentication.

Add `-insecure` if TLS cert is invalid.

Add `-proxy "http://127.0.0.1:8080"` to route through Caido/Burp.

## Output

sourcemapper writes the recovered source tree to the output directory, preserving the original module paths from the sourcemap:

```
decoded-sources/
  main/
    webpack:/
      src/
        components/
          Login.tsx
          Dashboard.tsx
        utils/
          api.ts
          auth.ts
```

After running, record the count:

```bash
find "<js_dir>/decoded-sources" -type f 2>/dev/null | wc -l
```

Decoded sources are automatically picked up by Phase 2 (api-mapper) and Phase 3 (taint-analyzer) since they scan `<js_dir>` recursively. No extra configuration needed.

## When decoding fails

- `no sourcemap found` — the JS file has no `sourceMappingURL` comment and no `.js.map` exists — skip, analysis proceeds on minified bundle
- `invalid JSON` — corrupted or truncated map file — skip this file, continue with others
- sourcemapper hangs (>60s) — kill and skip: `timeout 60 sourcemapper ...`
