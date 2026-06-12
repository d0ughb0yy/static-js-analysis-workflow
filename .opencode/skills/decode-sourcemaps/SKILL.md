---
name: decode-sourcemaps
description: Decode JavaScript source map files (.js.map) to recover original source code, filenames, and line mapping indexes for static analysis.
license: MIT
compatibility: opencode
metadata:
  category: security
  domain: static-analysis
  language: javascript
---

## What I do

I parse JavaScript source map files (.js.map) and recover the original source code that was used to build minified bundles. This is essential for accurate bug bounty static analysis because:

- Minified bundles have meaningless variable names and no whitespace
- Original sources reveal real function names, comments, and line numbers
- Line mapping indexes let you trace findings back to original source locations

## Input

A directory containing `.js.map` files (typically alongside their `.js` bundles).

## Output

For each source map decoded:
- Original source files written to `decoded-sources/<bundle-name>/<original-filename>`
- `mapping-index.json` containing generated line -> original line/column/name mappings

## Usage

Run the decoder via bash:

```bash
node .opencode/skills/decode-sourcemaps/decode-sourcemaps.js <input_dir> <output_dir>
```

Or invoke this skill and the agent will run it automatically.

## Dependencies

Requires the `source-map` npm package:

```bash
npm install source-map
```

## What the decoder produces

Given `app.js.map`, the decoder creates:

```
decoded-sources/
  app/
    src/
      components/
        Login.tsx
        Dashboard.tsx
      utils/
        api.ts
        auth.ts
    mapping-index.json
```

The `mapping-index.json` maps generated lines (from the minified bundle) back to original lines:

```json
{
  "src/components/Login.tsx": {
    "45": [{"originalLine": 12, "originalColumn": 4, "name": "handleLogin"}],
    "46": [{"originalLine": 13, "originalColumn": 8, "name": null}]
  }
}
```

This lets other agents report findings as `src/components/Login.tsx:12` instead of `app.js:45`.
