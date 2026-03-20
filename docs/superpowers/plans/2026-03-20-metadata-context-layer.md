# Metadata Context Layer Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a 14-dimension metadata context layer that feeds into confidence scoring, replacing the code-only confidence calculation with one that incorporates GitHub API metadata, dependency analysis, and code-extracted behavioral signals.

**Architecture:** Metadata fetch runs in parallel with code scan. Quick signals (GitHub API) add <1s latency. Deep scan (CVEs, contributors, star velocity) is opt-in. All metadata flows into a new `ConfidenceCalculator` that replaces `calculateVerdictConfidence()`. A new `CONDITIONAL_PASS` verdict covers "code clean but low confidence."

**Tech Stack:** TypeScript, GitHub REST API (native fetch), Next.js API routes, existing ScanEngine

**Spec:** `docs/superpowers/specs/2026-03-20-mcp-repo-safety-framework-design.md`

---

## Chunk 1: Types, Confidence Calculator, and Metadata Extractors

### Task 1: Add MetadataSignals and Caveat types to engine/types.ts

**Files:**
- Modify: `src/engine/types.ts:163` (Verdict type) and append new interfaces

- [ ] **Step 1: Add CONDITIONAL_PASS to Verdict type**

In `src/engine/types.ts:163`, change:
```typescript
export type Verdict = "SAFE" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";
```
to:
```typescript
export type Verdict = "SAFE" | "CONDITIONAL_PASS" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";
```

- [ ] **Step 2: Add MetadataSignals and Caveat interfaces**

Append to `src/engine/types.ts` after the ScanResponse interface (after line 223):

```typescript
// ============================================================
// METADATA SIGNALS (Phase 2 — confidence context layer)
// ============================================================

export interface MetadataSignals {
  author: {
    login: string;
    type: "User" | "Organization";
    accountAge: number;       // days
    publicRepos: number;
    followers: number;
    profileComplete: boolean; // has bio, email, or website
  } | null;

  repo: {
    stars: number;
    forks: number;
    age: number;              // days since created_at
    lastPush: string;         // ISO date
    openIssues: number;
    license: string | null;
    contributorCount?: number;       // deep scan only
    topContributorPct?: number;      // deep scan only
    starsPerDay?: number;            // deep scan only
  } | null;

  dependencies: {
    total: number;
    installHooks: string[];          // e.g. ["postinstall"]
    knownCves?: { id: string; severity: string }[];  // deep scan only
  };

  installInvasiveness: {
    externalPaths: string[];         // paths outside project dir
    dotfilesModified: string[];      // .bashrc, .zshrc, etc.
    toolConfigsModified: string[];   // .claude/*, .cursor/*, etc.
  };

  network: {
    outboundDomains: string[];
    phoneHome: boolean;
    corsPolicy: string | null;       // "*", specific origin, or null
    localhostBinding: string | null; // "127.0.0.1" or "0.0.0.0"
  };

  auth: {
    dangerousEndpoints: { name: string; authenticated: boolean }[];
  };

  fetchedAt: string;                 // ISO timestamp
  deepScan: boolean;                 // whether tier 3 ran
}

export interface Caveat {
  dimension: string;     // e.g. "repo_age", "cors_policy"
  severity: "info" | "warning" | "critical";
  text: string;          // human-readable
}
```

- [ ] **Step 3: Add metadata and caveats fields to OrchestratorResult**

In `src/lib/scan-orchestrator.ts`, add to the `OrchestratorResult` interface (around line 26, before `error?`):

```typescript
  /** Metadata signals collected from GitHub API and code analysis */
  metadata?: MetadataSignals;
  /** Human-readable context caveats */
  caveats?: Caveat[];
```

Add the import at the top:
```typescript
import type { ScanResult, ScanTarget, Verdict, TargetType, MetadataSignals, Caveat } from "@/engine/types";
```

- [ ] **Step 4: Add metadata and caveats to ScanResponse**

In `src/engine/types.ts`, update the `ScanResponse` interface (around line 213) to add:
```typescript
  metadata?: MetadataSignals;
  caveats?: Caveat[];
```

- [ ] **Step 5: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes (new types are additive, nothing consumes them yet)

- [ ] **Step 6: Commit**

```bash
git add src/engine/types.ts src/lib/scan-orchestrator.ts
git commit -m "feat: add MetadataSignals, Caveat types and CONDITIONAL_PASS verdict"
```

---

### Task 2: Create the Confidence Calculator

**Files:**
- Create: `src/engine/confidence.ts`

This replaces the inline `calculateVerdictConfidence()` in `scan-orchestrator.ts` with a new module that accepts both code findings and metadata signals.

- [ ] **Step 1: Create `src/engine/confidence.ts`**

```typescript
/**
 * Confidence Calculator — combines code scan findings with metadata signals
 * to produce a confidence score (0.0–1.0) and human-readable caveats.
 *
 * Replaces the old calculateVerdictConfidence() in scan-orchestrator.ts.
 */

import type { Finding, MetadataSignals, Caveat } from "./types";

/** Check if a rule ID indicates intent (not just capability) */
function isIntentRule(ruleId: string): boolean {
  // Import from scanner would create circular dep, so inline the set
  const INTENT_RULES = new Set([
    "ACR-S-004", "ACR-S-005", "ACR-S-006", "ACR-S-020",
    "ACR-S-019", "ACR-S-002", "ACR-S-017", "ACR-S-010",
    "ACR-S-018", "ACR-S-022", "ACR-S-015", "ACR-S-023",
    "ACR-S-001", "ACR-S-028", "ACR-S-027", "ACR-S-016",
    "ACR-M-001", "ACR-M-002", "ACR-M-003", "ACR-M-004",
    "ACR-M-005", "ACR-M-006", "ACR-M-007",
    "ACR-C-001", "ACR-C-002", "ACR-C-003",
    "ACR-V-001", "ACR-V-002", "ACR-V-003",
  ]);
  return INTENT_RULES.has(ruleId);
}

export interface ConfidenceResult {
  confidence: number;   // 0.0–1.0
  caveats: Caveat[];
}

/**
 * Calculate base confidence from code scan findings alone.
 */
function calculateBaseConfidence(findings: Finding[], shortCircuit: boolean): number {
  if (shortCircuit) return 0.95;

  if (findings.length === 0) return 0.60;

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const intentCount = findings.filter(f => isIntentRule(f.ruleId)).length;

  if (criticalCount >= 2 || (criticalCount >= 1 && intentCount >= 1)) return 0.90;
  if (highCount >= 3) return 0.80;
  if (findings.length <= 2) return 0.45;

  return 0.55;
}

/**
 * Apply metadata signal adjustments to base confidence.
 * Each signal produces a boost or penalty + optional caveat.
 */
function applyMetadataAdjustments(
  base: number,
  metadata: MetadataSignals | null | undefined,
): ConfidenceResult {
  if (!metadata) {
    return { confidence: base, caveats: [] };
  }

  let adj = 0;
  const caveats: Caveat[] = [];

  // --- Author credibility ---
  if (metadata.author) {
    const { type, accountAge, publicRepos } = metadata.author;
    if (type === "Organization" || (accountAge > 730 && publicRepos > 20)) {
      adj += 0.08;
    } else if (accountAge < 180 && publicRepos <= 2) {
      adj -= 0.10;
      caveats.push({
        dimension: "author_credibility",
        severity: "warning",
        text: "Author account is new with no track record",
      });
    }
  }

  // --- Repo vitals ---
  if (metadata.repo) {
    if (metadata.repo.age > 365) {
      adj += 0.05;
    } else if (metadata.repo.age < 90) {
      adj -= 0.08;
      caveats.push({
        dimension: "repo_age",
        severity: "warning",
        text: "Repository is less than 90 days old",
      });
    }

    // License
    if (metadata.repo.license) {
      const permissive = ["mit", "apache-2.0", "isc", "bsd-2-clause", "bsd-3-clause", "unlicense"];
      if (permissive.includes(metadata.repo.license.toLowerCase())) {
        adj += 0.03;
      }
    } else {
      adj -= 0.05;
      caveats.push({
        dimension: "license",
        severity: "info",
        text: "No license file found",
      });
    }

    // Deep scan: contributors
    if (metadata.repo.contributorCount !== undefined) {
      if (metadata.repo.contributorCount > 3) {
        adj += 0.05;
      } else if (metadata.repo.contributorCount <= 1) {
        adj -= 0.05;
        caveats.push({
          dimension: "contributor_concentration",
          severity: "info",
          text: "Single-author project",
        });
      }
    }

    // Deep scan: star velocity
    if (metadata.repo.starsPerDay !== undefined) {
      if (metadata.repo.starsPerDay > 50 && metadata.repo.age < 30) {
        adj -= 0.10;
        caveats.push({
          dimension: "star_velocity",
          severity: "warning",
          text: "Star growth pattern appears inorganic",
        });
      }
    }
  }

  // --- Dependencies ---
  if (metadata.dependencies) {
    if (metadata.dependencies.installHooks.length === 0) {
      adj += 0.03;
    } else {
      adj -= 0.05;
      caveats.push({
        dimension: "install_hooks",
        severity: "warning",
        text: `Package has install lifecycle hooks: ${metadata.dependencies.installHooks.join(", ")}`,
      });
    }

    // Deep scan: CVEs
    if (metadata.dependencies.knownCves) {
      const criticalCves = metadata.dependencies.knownCves.filter(
        c => c.severity === "critical" || c.severity === "high"
      );
      if (criticalCves.length > 0) {
        adj -= 0.15;
        caveats.push({
          dimension: "known_cves",
          severity: "critical",
          text: `${criticalCves.length} critical/high CVEs in dependencies`,
        });
      } else if (metadata.dependencies.knownCves.length === 0) {
        adj += 0.05;
      }
    }
  }

  // --- Install invasiveness ---
  if (metadata.installInvasiveness) {
    const totalExternal =
      metadata.installInvasiveness.externalPaths.length +
      metadata.installInvasiveness.dotfilesModified.length +
      metadata.installInvasiveness.toolConfigsModified.length;

    if (totalExternal <= 1) {
      adj += 0.03;
    } else if (totalExternal >= 5) {
      adj -= 0.10;
      caveats.push({
        dimension: "install_invasiveness",
        severity: "warning",
        text: `Modifies ${totalExternal} files outside project directory`,
      });
    }
  }

  // --- Network behavior ---
  if (metadata.network) {
    if (metadata.network.phoneHome) {
      adj -= 0.07;
      caveats.push({
        dimension: "phone_home",
        severity: "warning",
        text: "Phones home on startup without opt-out",
      });
    }

    if (metadata.network.corsPolicy === "*") {
      adj -= 0.08;
      caveats.push({
        dimension: "cors_policy",
        severity: "warning",
        text: "CORS wildcard (*) on local HTTP server",
      });
    }

    // If we have domain info and none are suspicious, small boost
    if (
      metadata.network.outboundDomains.length > 0 &&
      !metadata.network.phoneHome &&
      metadata.network.corsPolicy !== "*"
    ) {
      adj += 0.05;
    }
  }

  // --- Auth & access control ---
  if (metadata.auth) {
    const unauthDangerous = metadata.auth.dangerousEndpoints.filter(e => !e.authenticated);
    if (unauthDangerous.length > 0) {
      adj -= 0.12;
      for (const ep of unauthDangerous) {
        caveats.push({
          dimension: "auth_endpoints",
          severity: "critical",
          text: `Unauthenticated endpoint: ${ep.name}`,
        });
      }
    } else if (metadata.auth.dangerousEndpoints.length > 0) {
      // All dangerous endpoints are authenticated — good
      adj += 0.03;
    }
  }

  const confidence = Math.max(0.10, Math.min(0.98, base + adj));
  return { confidence, caveats };
}

/**
 * Main entry point: calculate confidence from findings + metadata.
 */
export function calculateConfidence(
  findings: Finding[],
  shortCircuit: boolean,
  metadata?: MetadataSignals | null,
): ConfidenceResult {
  const base = calculateBaseConfidence(findings, shortCircuit);
  return applyMetadataAdjustments(base, metadata);
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes (new file, nothing imports it yet)

- [ ] **Step 3: Commit**

```bash
git add src/engine/confidence.ts
git commit -m "feat: add confidence calculator with metadata signal adjustments"
```

---

### Task 3: Create the Metadata Extractors (code-derived signals)

**Files:**
- Create: `src/lib/metadata-extractors.ts`

Extracts Tier 2 signals (network behavior, filesystem scope, auth, install invasiveness) from code scan results and raw file content. These don't need GitHub API — they're derived from the code itself.

- [ ] **Step 1: Create `src/lib/metadata-extractors.ts`**

```typescript
/**
 * Metadata Extractors — derive behavioral signals from code content.
 * Extracts: install invasiveness, network behavior, auth patterns.
 * These are Tier 2 signals that don't require GitHub API access.
 */

import type { MetadataSignals } from "@/engine/types";

// Patterns for dotfile/config modification
const DOTFILE_PATTERNS = [
  /\.bashrc/gi,
  /\.zshrc/gi,
  /\.bash_profile/gi,
  /\.profile/gi,
  /\.zprofile/gi,
];

const TOOL_CONFIG_PATTERNS = [
  /\.claude\//gi,
  /\.cursor\//gi,
  /\.vscode\//gi,
  /\.codex/gi,
  /\.gemini/gi,
  /\.zed/gi,
];

const EXTERNAL_PATH_PATTERNS = [
  /\/usr\/local\//gi,
  /\/opt\//gi,
  /\/etc\//gi,
  /~\//g,
  /\$HOME\//gi,
  /process\.env\.HOME/gi,
  /os\.homedir\(\)/gi,
];

// Network patterns
const CORS_WILDCARD = /['"]?\*['"]?\s*(?:\/\/.*cors|.*access-control-allow-origin)/gi;
const CORS_HEADER_SET = /['"](Access-Control-Allow-Origin|cors)['"]\s*[,:]\s*['"]\*['"]/gi;
const LOCALHOST_BIND = /(?:listen|bind|host)\s*[\(:]?\s*['"]?(0\.0\.0\.0|127\.0\.0\.1|localhost)['"]?/gi;

// Phone-home: background fetch/http calls on startup/init
const PHONE_HOME_PATTERNS = [
  /setInterval\s*\(\s*(?:async\s*)?\(\)\s*=>\s*(?:.*fetch|.*http|.*request)/gi,
  /setTimeout\s*\(\s*(?:async\s*)?\(\)\s*=>\s*(?:.*fetch|.*http|.*request)/gi,
  /(?:check|version|update).*(?:fetch|http\.get|axios\.get|request)\s*\(/gi,
  /api\.github\.com/gi,
];

// Dangerous endpoint patterns
const DANGEROUS_ENDPOINT_PATTERNS = [
  { pattern: /(?:process|pid)[\-_.]?kill/gi, name: "process-kill" },
  { pattern: /(?:file|fs)[\-_.]?(?:delete|remove|unlink)/gi, name: "file-delete" },
  { pattern: /(?:shell|exec|spawn|system)\s*\(/gi, name: "shell-exec" },
  { pattern: /(?:shutdown|restart|reboot)/gi, name: "system-control" },
];

interface FileContent {
  filename: string;
  content: string;
}

/**
 * Extract install invasiveness signals from all repo files.
 */
export function extractInstallInvasiveness(
  files: FileContent[],
): MetadataSignals["installInvasiveness"] {
  const externalPaths = new Set<string>();
  const dotfilesModified = new Set<string>();
  const toolConfigsModified = new Set<string>();

  for (const file of files) {
    const content = file.content;

    for (const pattern of DOTFILE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) dotfilesModified.add(match[0]);
      }
    }

    for (const pattern of TOOL_CONFIG_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) toolConfigsModified.add(match[0]);
      }
    }

    for (const pattern of EXTERNAL_PATH_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) externalPaths.add(match[0]);
      }
    }
  }

  return {
    externalPaths: [...externalPaths],
    dotfilesModified: [...dotfilesModified],
    toolConfigsModified: [...toolConfigsModified],
  };
}

/**
 * Extract network behavior signals from all repo files.
 */
export function extractNetworkBehavior(
  files: FileContent[],
): MetadataSignals["network"] {
  const outboundDomains = new Set<string>();
  let phoneHome = false;
  let corsPolicy: string | null = null;
  let localhostBinding: string | null = null;

  // Domain extraction pattern: fetch("https://example.com/...") or http.get("...")
  const domainPattern = /(?:fetch|get|post|put|request|axios)\s*\(\s*[`'"](https?:\/\/([^/'"` ]+))/gi;

  for (const file of files) {
    const content = file.content;

    // Extract outbound domains
    domainPattern.lastIndex = 0;
    let match;
    while ((match = domainPattern.exec(content)) !== null) {
      if (match[2]) outboundDomains.add(match[2]);
    }

    // Check CORS
    CORS_WILDCARD.lastIndex = 0;
    CORS_HEADER_SET.lastIndex = 0;
    if (CORS_WILDCARD.test(content) || CORS_HEADER_SET.test(content)) {
      corsPolicy = "*";
    }

    // Check localhost binding
    LOCALHOST_BIND.lastIndex = 0;
    const bindMatch = LOCALHOST_BIND.exec(content);
    if (bindMatch) {
      localhostBinding = bindMatch[1];
    }

    // Check phone-home
    for (const pattern of PHONE_HOME_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        phoneHome = true;
        break;
      }
    }
  }

  return {
    outboundDomains: [...outboundDomains],
    phoneHome,
    corsPolicy,
    localhostBinding,
  };
}

/**
 * Extract auth & access control signals from all repo files.
 */
export function extractAuthSignals(
  files: FileContent[],
): MetadataSignals["auth"] {
  const dangerousEndpoints: { name: string; authenticated: boolean }[] = [];

  for (const file of files) {
    const content = file.content;

    for (const { pattern, name } of DANGEROUS_ENDPOINT_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        // Heuristic: check if auth middleware is nearby (within 20 lines)
        const lines = content.split("\n");
        let hasAuth = false;
        for (let i = 0; i < lines.length; i++) {
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            // Check surrounding 20 lines for auth patterns
            const context = lines.slice(Math.max(0, i - 20), i + 20).join("\n");
            if (/auth|middleware|bearer|token|session|cookie/i.test(context)) {
              hasAuth = true;
            }
          }
        }
        dangerousEndpoints.push({ name, authenticated: hasAuth });
      }
    }
  }

  return { dangerousEndpoints };
}

/**
 * Extract dependency lifecycle signals from package.json content.
 */
export function extractDependencySignals(
  packageJsonContent: string | null,
): MetadataSignals["dependencies"] {
  if (!packageJsonContent) {
    return { total: 0, installHooks: [] };
  }

  try {
    const pkg = JSON.parse(packageJsonContent);
    const deps = Object.keys(pkg.dependencies || {}).length +
                 Object.keys(pkg.devDependencies || {}).length;

    const hookNames = ["preinstall", "install", "postinstall", "prepare", "prepublish"];
    const installHooks = hookNames.filter(
      h => pkg.scripts && typeof pkg.scripts[h] === "string"
    );

    return { total: deps, installHooks };
  } catch {
    return { total: 0, installHooks: [] };
  }
}

/**
 * Build partial MetadataSignals from code analysis only (no GitHub API).
 * Used as Tier 2 signals that get merged with Tier 1 GitHub API data.
 */
export function extractCodeMetadata(
  files: FileContent[],
  packageJsonContent: string | null,
): Pick<MetadataSignals, "installInvasiveness" | "network" | "auth" | "dependencies"> {
  return {
    installInvasiveness: extractInstallInvasiveness(files),
    network: extractNetworkBehavior(files),
    auth: extractAuthSignals(files),
    dependencies: extractDependencySignals(packageJsonContent),
  };
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes

- [ ] **Step 3: Commit**

```bash
git add src/lib/metadata-extractors.ts
git commit -m "feat: add code-derived metadata extractors for network, auth, and invasiveness signals"
```

---

## Chunk 2: GitHub API Integration

### Task 4: Create the GitHub Metadata Fetcher

**Files:**
- Create: `src/lib/github-metadata.ts`

Fetches Tier 1 signals from GitHub REST API (author profile, repo vitals, license). Uses native `fetch()` — no new dependencies needed.

- [ ] **Step 1: Create `src/lib/github-metadata.ts`**

```typescript
/**
 * GitHub Metadata Fetcher — retrieves repo and author signals from GitHub REST API.
 * Tier 1 (quick, <1s): author profile, repo vitals, license.
 * Tier 3 (deep, opt-in): contributors, star velocity.
 *
 * Uses native fetch. Requires GITHUB_TOKEN env var for higher rate limits (optional).
 * Without a token: 60 requests/hour. With token: 5000 requests/hour.
 */

import type { MetadataSignals } from "@/engine/types";

const GITHUB_API = "https://api.github.com";
const REQUEST_TIMEOUT = 5000; // 5s per request

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "AgentCanary/0.2.0",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

async function githubFetch(path: string): Promise<unknown | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    const res = await fetch(`${GITHUB_API}${path}`, {
      headers: getHeaders(),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  const now = Date.now();
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}

/**
 * Fetch Tier 1 quick signals: author profile + repo vitals.
 * Runs 2 parallel API calls, completes in <1s.
 */
export async function fetchQuickMetadata(
  owner: string,
  repo: string,
): Promise<Pick<MetadataSignals, "author" | "repo">> {
  const [userData, repoData] = await Promise.all([
    githubFetch(`/users/${owner}`),
    githubFetch(`/repos/${owner}/${repo}`),
  ]);

  let author: MetadataSignals["author"] = null;
  if (userData && typeof userData === "object") {
    const u = userData as Record<string, unknown>;
    author = {
      login: String(u.login || owner),
      type: u.type === "Organization" ? "Organization" : "User",
      accountAge: u.created_at ? daysSince(String(u.created_at)) : 0,
      publicRepos: Number(u.public_repos || 0),
      followers: Number(u.followers || 0),
      profileComplete: Boolean(u.bio || u.email || u.blog),
    };
  }

  let repoInfo: MetadataSignals["repo"] = null;
  if (repoData && typeof repoData === "object") {
    const r = repoData as Record<string, unknown>;
    const license = r.license as Record<string, unknown> | null;
    const repoAge = r.created_at ? daysSince(String(r.created_at)) : 0;

    repoInfo = {
      stars: Number(r.stargazers_count || 0),
      forks: Number(r.forks_count || 0),
      age: repoAge,
      lastPush: String(r.pushed_at || ""),
      openIssues: Number(r.open_issues_count || 0),
      license: license ? String(license.spdx_id || license.key || null) : null,
    };
  }

  return { author, repo: repoInfo };
}

/**
 * Fetch Tier 3 deep signals: contributors + star velocity.
 * Takes 2-5s additional. Only called when deep scan is enabled.
 */
export async function fetchDeepMetadata(
  owner: string,
  repo: string,
  existingRepo: MetadataSignals["repo"],
): Promise<Partial<Pick<NonNullable<MetadataSignals["repo"]>, "contributorCount" | "topContributorPct" | "starsPerDay">>> {
  const result: {
    contributorCount?: number;
    topContributorPct?: number;
    starsPerDay?: number;
  } = {};

  // Contributors
  const contributors = await githubFetch(`/repos/${owner}/${repo}/contributors?per_page=100`);
  if (Array.isArray(contributors) && contributors.length > 0) {
    result.contributorCount = contributors.length;
    const totalContributions = contributors.reduce(
      (sum: number, c: Record<string, unknown>) => sum + Number(c.contributions || 0),
      0,
    );
    if (totalContributions > 0) {
      const topContributions = Number((contributors[0] as Record<string, unknown>).contributions || 0);
      result.topContributorPct = Math.round((topContributions / totalContributions) * 100);
    }
  }

  // Star velocity (stars / age in days)
  if (existingRepo && existingRepo.age > 0) {
    result.starsPerDay = Math.round((existingRepo.stars / existingRepo.age) * 100) / 100;
  }

  return result;
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes

- [ ] **Step 3: Commit**

```bash
git add src/lib/github-metadata.ts
git commit -m "feat: add GitHub API metadata fetcher for author and repo signals"
```

---

## Chunk 3: Wire Everything Together in the Orchestrator

### Task 5: Integrate metadata into scanGitHubRepo

**Files:**
- Modify: `src/lib/scan-orchestrator.ts`

This is the main integration point. The orchestrator needs to:
1. Run metadata fetch in parallel with code scan
2. Pass metadata to the confidence calculator
3. Apply the new CONDITIONAL_PASS verdict logic
4. Include metadata + caveats in the result

- [ ] **Step 1: Add imports to scan-orchestrator.ts**

At the top of `src/lib/scan-orchestrator.ts`, add:

```typescript
import type { ScanResult, ScanTarget, Verdict, TargetType, MetadataSignals, Caveat } from "@/engine/types";
import { calculateConfidence } from "@/engine/confidence";
import { fetchQuickMetadata, fetchDeepMetadata } from "./github-metadata";
import { extractCodeMetadata } from "./metadata-extractors";
import { parseGitHubUrl } from "./github-fetcher";
```

(Replace the existing import of `ScanResult, ScanTarget, Verdict, TargetType` and add the new ones.)

- [ ] **Step 2: Add metadata and caveats to OrchestratorResult**

Update the `OrchestratorResult` interface to include:

```typescript
export interface OrchestratorResult {
  success: boolean;
  results: ScanResult[];
  aggregateVerdict: Verdict;
  aggregateScore: number;
  totalFindings: number;
  filesScanned: number;
  rulesLoaded: number;
  scanDuration: number;
  shortCircuit?: boolean;
  verdictConfidence?: number;
  metadata?: MetadataSignals;
  caveats?: Caveat[];
  error?: string;
}
```

- [ ] **Step 3: Add `deepScan` parameter to `scanGitHubRepo`**

Change the signature:
```typescript
export async function scanGitHubRepo(url: string, deepScan = false): Promise<OrchestratorResult> {
```

- [ ] **Step 4: Add parallel metadata fetch inside scanGitHubRepo**

After the clone succeeds and before the `try` block's file walking, add the metadata fetch. Replace the `try` block content (lines 66-125) with:

```typescript
  try {
    const parsed = parseGitHubUrl(url);

    // Start metadata fetch in parallel with code scan
    const metadataPromise = parsed
      ? fetchQuickMetadata(parsed.owner, parsed.repo).catch(() => ({ author: null, repo: null }))
      : Promise.resolve({ author: null, repo: null });

    // Walk the repo files
    const files = walkDirectory(clone.localPath);
    const results: ScanResult[] = [];

    // Find package.json for dependency extraction
    const packageJsonFile = files.find(
      f => f.relativePath === "package.json" || f.relativePath.endsWith("/package.json")
    );
    const packageJsonContent = packageJsonFile?.content ?? null;

    // Extract code-derived metadata (Tier 2)
    const codeFiles = files.map(f => ({ filename: f.relativePath, content: f.content }));
    const codeMetadata = extractCodeMetadata(codeFiles, packageJsonContent);

    // Scan each file (existing logic)
    for (const file of files) {
      if (file.isDocFile) continue;

      if (file.type === "npm_package") {
        const extraTargets = extractPackageJsonTargets(file.content, file.relativePath);
        for (const extra of extraTargets) {
          const extraResult = await engine.scan(extra);
          if (extraResult.findings.length > 0) results.push(extraResult);
        }
      }

      if (file.type === "config_file" && file.relativePath.toLowerCase().endsWith(".json")) {
        const toolTargets = extractToolDefinitionTargets(file.content, file.relativePath);
        for (const tool of toolTargets) {
          const toolResult = await engine.scan(tool);
          if (toolResult.findings.length > 0) results.push(toolResult);
        }
      }

      const target: ScanTarget = {
        content: file.content,
        filename: file.relativePath,
        type: file.type,
        metadata: { isTestFile: file.isTestFile },
      };
      const result = await engine.scan(target);

      if (file.isTestFile) {
        for (const f of result.findings) {
          if (f.severity === "critical") f.severity = "medium";
          else if (f.severity === "high") f.severity = "low";
        }
        result.score = result.findings.length === 0 ? 100 :
          Math.max(0, Math.round(100 - result.findings.reduce((sum, f) => {
            const pen: Record<string, number> = { critical: 40, high: 25, medium: 10, low: 3, info: 0 };
            const factor = isIntentRule(f.ruleId) ? 1.0 : 0.4;
            return sum + (pen[f.severity] || 5) * factor;
          }, 0)));
        result.verdict = result.score >= 80 ? "SAFE" : result.score >= 50 ? "CAUTION" : result.score >= 20 ? "SUSPICIOUS" : "DANGEROUS";
      }

      results.push(result);
    }

    // Await GitHub metadata (should be done by now — ran in parallel)
    const githubMeta = await metadataPromise;

    // Deep scan: fetch additional signals if enabled
    let deepSignals: { contributorCount?: number; topContributorPct?: number; starsPerDay?: number } = {};
    if (deepScan && parsed && githubMeta.repo) {
      deepSignals = await fetchDeepMetadata(parsed.owner, parsed.repo, githubMeta.repo).catch(() => ({}));
    }

    // Merge all metadata signals
    const metadata: MetadataSignals = {
      author: githubMeta.author,
      repo: githubMeta.repo ? {
        ...githubMeta.repo,
        ...deepSignals,
      } : null,
      dependencies: codeMetadata.dependencies,
      installInvasiveness: codeMetadata.installInvasiveness,
      network: codeMetadata.network,
      auth: codeMetadata.auth,
      fetchedAt: new Date().toISOString(),
      deepScan,
    };

    return buildAggregateResult(results, rulesLoaded, files.length, startMs, metadata);
  } finally {
    clone.cleanupFn?.();
  }
```

- [ ] **Step 5: Update buildAggregateResult to use new confidence calculator**

Replace the `buildAggregateResult` function with:

```typescript
function buildAggregateResult(
  results: ScanResult[],
  rulesLoaded: number,
  filesScanned: number,
  startMs: number,
  metadata?: MetadataSignals,
): OrchestratorResult {
  const allFindings = results.flatMap((r) => r.findings);
  const shortCircuit = results.some((r) => r.shortCircuit);

  const worstScore = shortCircuit
    ? 0
    : results.length > 0
      ? Math.min(...results.map((r) => r.score))
      : 100;

  // Use new confidence calculator with metadata
  const { confidence, caveats } = calculateConfidence(allFindings, shortCircuit, metadata);

  // New verdict logic: CONDITIONAL_PASS when code is clean but confidence is low
  let verdict: Verdict;
  if (shortCircuit) {
    verdict = "DANGEROUS";
  } else if (worstScore >= 80 && confidence >= 0.70) {
    verdict = "SAFE";
  } else if (worstScore >= 80 && confidence < 0.70) {
    verdict = "CONDITIONAL_PASS";
  } else if (worstScore >= 50) {
    verdict = "CAUTION";
  } else if (worstScore >= 20) {
    verdict = "SUSPICIOUS";
  } else {
    verdict = "DANGEROUS";
  }

  return {
    success: true,
    results,
    aggregateVerdict: verdict,
    aggregateScore: worstScore,
    totalFindings: allFindings.length,
    filesScanned,
    rulesLoaded,
    scanDuration: Date.now() - startMs,
    shortCircuit,
    verdictConfidence: confidence,
    metadata,
    caveats,
  };
}
```

- [ ] **Step 6: Remove the old calculateVerdictConfidence function**

Delete the old `calculateVerdictConfidence` function (lines ~220-245 in scan-orchestrator.ts) and the `scoreToVerdict` function. They're replaced by the confidence calculator and inline verdict logic.

- [ ] **Step 7: Update scanContent to pass no metadata (keeps backward compat)**

The `scanContent` function should call `buildAggregateResult` without metadata:
```typescript
  const result = await engine.scan(target);
  return buildAggregateResult([result], rulesLoaded, 1, startMs);
```
This is already correct — `metadata` parameter is optional and defaults to `undefined`.

- [ ] **Step 8: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes

- [ ] **Step 9: Commit**

```bash
git add src/lib/scan-orchestrator.ts
git commit -m "feat: wire metadata context layer into scan orchestrator with parallel fetch"
```

---

### Task 6: Update the GitHub API route to pass deepScan parameter

**Files:**
- Modify: `src/app/api/scan/github/route.ts`

- [ ] **Step 1: Update route to accept deepScan**

Replace the route handler body (in `src/app/api/scan/github/route.ts`):

```typescript
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url, deepScan } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json(
        { success: false, error: "Missing or invalid 'url' parameter" },
        { status: 400 }
      );
    }

    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return NextResponse.json(
        { success: false, error: "Invalid GitHub URL. Expected format: https://github.com/owner/repo" },
        { status: 400 }
      );
    }

    const result = await scanGitHubRepo(url, Boolean(deepScan));

    return NextResponse.json(result, {
      status: result.success ? 200 : 500,
    });
  } catch (err) {
    console.error("GitHub scan error:", err);
    return NextResponse.json(
      { success: false, error: `Scan failed: ${(err as Error).message}` },
      { status: 500 }
    );
  }
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes

- [ ] **Step 3: Commit**

```bash
git add src/app/api/scan/github/route.ts
git commit -m "feat: add deepScan parameter to GitHub scan API route"
```

---

## Chunk 4: UI Updates

### Task 7: Update the frontend for CONDITIONAL_PASS and caveats

**Files:**
- Modify: `src/app/page.tsx`

- [ ] **Step 1: Add CONDITIONAL_PASS to types and config**

In `src/app/page.tsx`, update the Verdict type (line 6):
```typescript
type Verdict = "SAFE" | "CONDITIONAL_PASS" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";
```

Add to `VERDICT_CONFIG` (after SAFE entry):
```typescript
  CONDITIONAL_PASS: { emoji: "\u{1F7E1}", color: "text-yellow-400", bg: "bg-yellow-950/50", border: "border-yellow-800" },
```

- [ ] **Step 2: Add caveats to ScanResponse interface**

In the frontend `ScanResponse` interface (around line 26), add:
```typescript
  caveats?: { dimension: string; severity: string; text: string }[];
```

- [ ] **Step 3: Add deep scan toggle to the GitHub input area**

Add state for deepScan:
```typescript
const [deepScan, setDeepScan] = useState(false);
```

In the GitHub mode input area (after the URL input, around line 204), add:
```typescript
                <label className="flex items-center gap-2 mt-3 text-sm text-gray-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={deepScan}
                    onChange={(e) => setDeepScan(e.target.checked)}
                    className="rounded border-gray-600 bg-gray-800"
                  />
                  Deep scan (slower — checks CVEs + contributor patterns)
                </label>
```

- [ ] **Step 4: Pass deepScan in the fetch call**

Update the GitHub fetch call (around line 78-82):
```typescript
        response = await fetch("/api/scan/github", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: githubUrl.trim(), deepScan }),
        });
```

- [ ] **Step 5: Add caveats display to ScanResults component**

In the `ScanResults` component, after the verdict banner's short-circuit message (around line 322), add:

```typescript
        {/* Caveats */}
        {data.caveats && data.caveats.length > 0 && (
          <div className="mt-3 space-y-1">
            {data.caveats.map((caveat, i) => (
              <div key={i} className="text-sm text-left">
                <span className={
                  caveat.severity === "critical" ? "text-red-400" :
                  caveat.severity === "warning" ? "text-yellow-400" :
                  "text-gray-400"
                }>
                  {caveat.severity === "critical" ? "\u{1F6A8}" : "\u{26A0}\u{FE0F}"}{" "}
                  {caveat.text}
                </span>
              </div>
            ))}
          </div>
        )}
```

- [ ] **Step 6: Verify build**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes

- [ ] **Step 7: Manual smoke test**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npm run dev`
Open http://localhost:3000

Test 1: Scan `https://github.com/davideast/stitch-mcp` → Should show SAFE with higher confidence than before
Test 2: Scan same repo with deep scan checked → Should show contributor info
Test 3: Paste malicious example → Should still show DANGEROUS (no regression)

- [ ] **Step 8: Commit**

```bash
git add src/app/page.tsx
git commit -m "feat: add CONDITIONAL_PASS verdict, caveats display, and deep scan toggle to UI"
```

---

### Task 8: Update version to v0.2.0

**Files:**
- Modify: `package.json:2` (version field)
- Modify: `src/app/page.tsx:157-159` (version badge)

- [ ] **Step 1: Bump version**

In `package.json`, change `"version": "0.1.0"` to `"version": "0.2.0"`.

In `src/app/page.tsx`, change the version badge text from `v0.1.0 MVP` to `v0.2.0`.

- [ ] **Step 2: Final build verification**

Run: `cd /Users/muellah/_muellah/AI/Claude/AgentCanary && npx next build`
Expected: Build passes with zero errors

- [ ] **Step 3: Commit**

```bash
git add package.json src/app/page.tsx
git commit -m "chore: bump version to v0.2.0 — metadata context layer"
```

---

## Summary

| Task | What it does | Files |
|------|-------------|-------|
| 1 | Add types (MetadataSignals, Caveat, CONDITIONAL_PASS) | `types.ts`, `scan-orchestrator.ts` |
| 2 | Create confidence calculator | `engine/confidence.ts` (new) |
| 3 | Create code-derived metadata extractors | `lib/metadata-extractors.ts` (new) |
| 4 | Create GitHub API metadata fetcher | `lib/github-metadata.ts` (new) |
| 5 | Wire metadata into scan orchestrator | `lib/scan-orchestrator.ts` |
| 6 | Update API route for deepScan param | `api/scan/github/route.ts` |
| 7 | Update UI for caveats + CONDITIONAL_PASS | `app/page.tsx` |
| 8 | Bump version to v0.2.0 | `package.json`, `app/page.tsx` |
