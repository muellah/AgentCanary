# Upload UI Rework — Design Spec

**Date:** 2026-03-19
**Status:** Approved
**Author:** AgentCanary team

## Summary

Replace the current "Paste / Upload" tab (code snippet textarea) with a proper file upload experience supporting `.md`, `.zip`, `.json`, and `.yaml` skill/plugin formats. Add pre-scan self-protection against zip bombs, path traversal, polyglot files, and non-skill content. Add sample test fixtures for demos.

## Tab Structure

Two tabs with clear scope labels:

| Tab | Label | Subtitle | Input | Scans |
|-----|-------|----------|-------|-------|
| ⚡ GitHub Repo | GitHub Repo | MCP Servers & Skill Repos | GitHub URL | Full source tree via clone |
| 📁 Upload File | Upload File | Skills, Plugins & Tool Definitions | File drag-drop/browse | Text-based skill content only |

**Rationale:** MCP servers are complex code projects best analyzed from source via GitHub. Skills/plugins are portable text bundles distributed as files. This separation avoids the complexity of analyzing arbitrary MCP server binaries.

## Upload Tab Layout

Top to bottom:
1. **Drop zone** — dashed-border area, supports drag-and-drop and browse button. If user drags multiple files, show inline error: "Please upload one file at a time." and accept nothing.
2. **File inspector panel** — appears after the server returns validation results (see two-step API flow below). Shows filename, size, format detection, validation badges, file tree (for zips). Shows a spinner while the server validates.
3. **Scan button** — appears after validation passes, label adapts: "Scan File" / "Scan Plugin" / "Scan Config"
4. **Sample bar** — always visible: "Try a sample: 🟢 Safe skill · 🔴 Malicious skill · 📦 Plugin bundle"

**Error states:** If the server returns a non-422 error (500, timeout, network failure), the inspector panel shows a red error box with the message and a "Try again" button. Upload request timeout: 30 seconds.

## Accepted Formats

| Extension | Type | Max size | Detection |
|-----------|------|----------|-----------|
| `.md` | Single skill file | 1MB | YAML frontmatter with `name:`/`description:`, or markdown with instructional content |
| `.zip` | Plugin bundle | 10MB compressed, 50MB decompressed | Contains `skills/`, `.claude-plugin/`, `SKILL.md`, `.mcp.json`, or `settings.json` |
| `.json` | Tool definitions or MCP config | 1MB | Objects with `name` + `description` + schema, or `mcpServers` key |
| `.yaml` / `.yml` | MCP/tool config | 512KB | Contains `mcpServers`, `tools`, or `servers` keys |

**Rejection message for non-skill content:** "This doesn't appear to be a skill file, plugin bundle, or tool definition. AgentCanary scans agent-related files only."

## Self-Protection (4 Layers)

### Layer 1 — Client-side quick reject (frontend, instant)
- **Default deny:** Reject any file extension not in the Accepted Formats table above
- **Extension block (explicit):** Reject `.exe`, `.dll`, `.so`, `.dylib`, `.app`, `.dmg`, `.sh`, `.bat`, `.cmd`, `.ps1`
- **Size check:** Reject files over format-specific size limits
- **MIME sniff:** Reject `application/x-executable`, `application/x-mach-binary`, etc.

### Layer 2 — Zip safety (API route, before extraction)
- **Zip bomb detection:** Read central directory first. Reject if decompressed/compressed ratio > 100x, decompressed > 50MB, or entry count > 500
- **Path traversal:** Reject entries containing `..` or absolute paths starting with `/`
- **Symlink attack:** Skip symlink entries
- **Nested zips:** No recursion — one level only

### Layer 3 — Content safety (API route, after extraction)
- **Polyglot detection:** Check for binary magic bytes (ELF, Mach-O, PE, PDF) despite text extension
- **Per-file size cap:** Individual files within zip capped at 1MB
- **Encoding check:** Must be valid UTF-8. Reject binary content masquerading as text.

### Layer 4 — Process isolation
- Extract to `/tmp/agentcanary-upload-XXXX/` (random name)
- Cleanup after scan completes. A 5-minute garbage collector removes any temp directories older than 5 minutes (covers abandoned uploads where no scan was initiated). In-progress scans are never interrupted by the GC.
- No extracted content is ever executed — read-only text analysis only

## File Inspector Panel

### Single `.md` file
```
📄 SKILL.md                                    2.1 KB
✓ Valid UTF-8  ✓ Skill file detected  ✓ No binary content

[Scan File]
```

### `.zip` plugin bundle
```
📦 knowledge-spreader-plugin.zip              24.6 KB → 38.5 KB
✓ Safe to extract  ✓ Plugin format  ✓ No path traversal  ✓ 29 entries

├── .claude-plugin/plugin.json          ← plugin metadata
├── .mcp.json                           ← MCP server config (5 servers)
├── settings.json                       ← permissions (12 allow rules)
└── skills/ (11 SKILL.md files)

[Scan Plugin]
```

### Rejected file
```
⚠️ report-2024.pdf                            3.2 MB
✗ Not a skill file — PDF binary detected

This doesn't appear to be a skill file, plugin bundle, or tool definition.
AgentCanary scans agent-related files only.
```

## Sample Fixtures

Three bundled test files served from `public/samples/`:

| Sample | File | Content | Expected Verdict |
|--------|------|---------|-----------------|
| 🟢 Safe skill | `safe-example.md` | Clean SKILL.md with legitimate instructions | SAFE |
| 🔴 Malicious skill | `malicious-example.md` | Clawhub SKILL.md with base64 shell command + fake download | DANGEROUS |
| 📦 Plugin bundle | `suspicious-plugin.zip` | 2 skills + malicious `.mcp.json` (attacker URL) + overly broad permissions | SUSPICIOUS |

Clicking a sample triggers the same flow as a normal upload (inspector → scan).

## API Changes

### Two-step API flow

The upload uses two sequential API calls:

1. **Validate:** `POST /api/scan/upload/validate` — receives the file, runs Layers 1-3 checks, returns inspector data (format, file tree, validation badges). Does NOT run the security scan yet.
2. **Scan:** `POST /api/scan/upload/scan` — receives a `sessionId` from the validate step, runs the full security scan on the already-extracted files. Returns `OrchestratorResult`.

This separation allows the inspector panel to show validation results before the user commits to a full scan.

### Route 1: `POST /api/scan/upload/validate`

Accepts `multipart/form-data` (binary file upload).

**Request:**
```
POST /api/scan/upload/validate
Content-Type: multipart/form-data

file: <binary data>
```

**Response (HTTP 200 — validation passed):**
```json
{
  "success": true,
  "sessionId": "upload-1710885600-abc123",
  "validation": {
    "format": "zip_plugin",
    "filename": "knowledge-spreader-plugin.zip",
    "compressedSize": 24629,
    "decompressedSize": 39475,
    "extractedFiles": 29,
    "fileTree": [
      { "path": ".claude-plugin/plugin.json", "label": "plugin metadata" },
      { "path": ".mcp.json", "label": "MCP server config (5 servers)" },
      { "path": "settings.json", "label": "permissions (12 allow rules)" },
      { "path": "skills/", "label": "11 SKILL.md files", "isDir": true }
    ],
    "checks": {
      "zipBomb": "pass",
      "pathTraversal": "pass",
      "binaryContent": "pass",
      "skillContent": "pass"
    }
  }
}
```

**Validation failure response (HTTP 422):**
```json
{
  "success": false,
  "validation": {
    "format": "unknown",
    "checks": { "zipBomb": "fail" }
  },
  "error": "Suspicious archive: decompression ratio exceeds 100x (possible zip bomb)"
}
```

For zips that pass safety checks but contain zero skill-related files, return HTTP 422 with `skillContent: "fail"` and the standard rejection message.

### Route 2: `POST /api/scan/upload/scan`

Runs the full security scan on an already-validated upload.

**Request:**
```json
{ "sessionId": "upload-1710885600-abc123" }
```

**Response:** Standard `OrchestratorResult` plus the validation metadata:
```json
{
  "uploadValidation": {
    "format": "zip_plugin" | "skill_md" | "tool_json" | "config_yaml",
    "extractedFiles": 29,
    "compressedSize": 24629,
    "decompressedSize": 39475,
    "checks": {
      "zipBomb": "pass" | "fail",
      "pathTraversal": "pass" | "fail",
      "binaryContent": "pass" | "fail",
      "skillContent": "pass" | "fail"
    }
  },
  "success": true,
  "results": [...],
  "aggregateVerdict": "SAFE",
  "aggregateScore": 100,
  ...
}
```

**Validation failure response (HTTP 422):**
```json
{
  "success": false,
  "uploadValidation": {
    "format": "unknown",
    "checks": {
      "zipBomb": "fail"
    }
  },
  "error": "Suspicious archive: decompression ratio exceeds 100x (possible zip bomb)"
}
```

The old `/api/scan/file` route remains for backward compatibility but is unused by the new UI.

### Scan results for zip bundles

For a zip containing multiple files, the orchestrator produces **one result per scannable file**. Each SKILL.md, `.mcp.json`, `settings.json`, `plugin.json`, and tool definition JSON gets its own entry in the `results` array with its own findings. The aggregate verdict uses the same "worst file wins" + short-circuit logic as GitHub repo scans.

Config files (`.mcp.json`, `settings.json`) are scanned as `config_file` type. Plugin metadata (`plugin.json`) is scanned as `config_file` type. SKILL.md files are scanned as `skill_file` type.

## Files Changed

| File | Change |
|------|--------|
| `src/app/page.tsx` | Replace paste textarea with drop zone + file inspector + sample bar |
| `src/app/api/scan/upload/validate/route.ts` | New: multipart upload validation endpoint (Layers 1-3, returns inspector data) |
| `src/app/api/scan/upload/scan/route.ts` | New: scan endpoint accepting sessionId from validate step |
| `src/lib/upload-validator.ts` | New: zip safety, polyglot detection, skill content validation, session management |
| `src/lib/scan-orchestrator.ts` | Add `scanUploadedFile()` — scans single files and extracted zip bundles (one result per file) |
| `public/samples/safe-example.md` | New: clean skill sample |
| `public/samples/malicious-example.md` | New: clawhub malicious sample |
| `public/samples/suspicious-plugin.zip` | New: plugin bundle with suspicious MCP config |

## Acceptance Criteria

1. **Upload tab:** Dropping a `.md` file shows the inspector panel with validation badges, then clicking Scan produces results
2. **Zip upload:** Dropping the `knowledge-spreader-plugin.zip` sample shows file tree with 29 entries and "Plugin format" badge
3. **Zip bomb:** A crafted zip with >100x compression ratio is rejected at Layer 2 with "possible zip bomb" error
4. **Path traversal:** A zip with `../../etc/passwd` entry is rejected at Layer 2
5. **Polyglot:** A renamed `.exe` with `.md` extension is caught by binary magic byte detection (Layer 3)
6. **Non-skill content:** A random text file (`.md` without skill content) is rejected with "not a skill file" message
7. **Multi-file drag:** Dragging 2+ files shows "Please upload one file at a time" error
8. **Extension reject:** Uploading a `.exe` file is rejected client-side instantly (Layer 1)
9. **Sample fixtures:** Each of the 3 samples produces its expected verdict (SAFE, DANGEROUS, SUSPICIOUS)
10. **Backward compat:** The old `/api/scan/file` JSON route still works
11. **Cleanup:** Temp directories under `/tmp/agentcanary-upload-*` are removed after scan completes
12. **GitHub tab:** GitHub repo scanning still works exactly as before (no regressions)

## Out of Scope

- MCP server binary analysis (use GitHub repo tab instead)
- Multiple file upload in one drag (single file/zip at a time)
- File upload progress bars (files are small, <10MB)
- Persisting upload history
