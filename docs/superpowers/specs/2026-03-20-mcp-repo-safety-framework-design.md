# MCP Repo Safety Assessment Framework — AgentCanary Phase 2

**Date:** 2026-03-20
**Status:** Approved
**Scope:** Add metadata/context dimensions to AgentCanary beyond code-level scanning

---

## Problem

AgentCanary v0.1 MVP is a code-level static scanner. It runs 42 rules across 4 phases (static, heuristic, semantic, composite) and produces a score + verdict. This works well for detecting malicious patterns in code, but it cannot assess **context signals** that dramatically affect how much you should trust a repo:

- A clean-code repo by a brand-new GitHub account with suspicious star growth is not the same as a clean-code repo by a verified Google org.
- A repo that modifies 10+ dotfiles and exposes an unauthenticated process-kill endpoint is riskier than one that stays in its own directory.
- A repo with unpatched critical CVEs in dependencies is riskier than one with a clean lockfile.

The current confidence score reflects this gap: stitch-mcp (a legitimate Google DevRel project) gets 50% confidence on a SAFE verdict because AC lacks the metadata to be more certain.

## Design Decisions

1. **Hybrid fetch strategy** — Quick metadata signals (stars, age, license, author) are fetched at scan time via GitHub REST API (<1s). Heavy analysis (CVE audit, star velocity, contributor concentration) is opt-in "deep scan" mode.
2. **Confidence modifier, not separate score** — Metadata dimensions feed into the confidence percentage, not the code score. Code score answers "what did we find in the code?" Confidence answers "how much should you trust that score given everything else we know?"
3. **Parallel execution** — Metadata fetch runs concurrently with code scan. No added latency for quick signals.
4. **Graceful degradation** — If GitHub API fails or no token is configured, confidence falls back to code-only calculation.

## Architecture

```
                          ┌─────────────────────┐
  GitHub URL ────────────►│   GitHub Fetcher     │
                          │  (existing: clone)   │
                          └──────┬──────────────┘
                                 │
                    ┌────────────┼────────────────┐
                    ▼                              ▼
         ┌──────────────────┐           ┌──────────────────┐
         │  Code Scanner    │           │  Metadata Fetcher │
         │  (existing)      │           │  (NEW — Phase 2)  │
         │                  │           │                    │
         │  Static → Heur   │           │  Quick signals:    │
         │  → Semantic →    │           │  • repo vitals     │
         │  Composite       │           │  • author profile  │
         │                  │           │  • license check   │
         │  Output:         │           │  • dep lifecycle   │
         │  score + findings│           │  • install scope   │
         └────────┬─────────┘           │                    │
                  │                     │  Deep scan (opt):  │
                  │                     │  • CVE audit       │
                  │                     │  • star velocity   │
                  │                     │  • contributor     │
                  │                     │    concentration   │
                  │                     │                    │
                  │                     │  Output:           │
                  │                     │  MetadataSignals   │
                  │                     └────────┬───────────┘
                  │                              │
                  ▼                              ▼
         ┌───────────────────────────────────────────────┐
         │         Confidence Calculator (NEW)            │
         │                                               │
         │  Inputs: code score, findings, MetadataSignals │
         │  Output: confidence 0.0–1.0 + caveats[]       │
         │                                               │
         │  Replaces current calculateVerdictConfidence() │
         └───────────────────────┬───────────────────────┘
                                 │
                                 ▼
                        Final ScanResult:
                        score: 90 (code only)
                        confidence: 0.88 (code + metadata)
                        verdict: SAFE
                        caveats: ["repo < 90 days old"]
```

## The 14 Dimensions

### Tier 1: Quick Signals (at scan time, <1s)

| # | Dimension | Data Source | Signal Extracted | Confidence Impact |
|---|-----------|-------------|------------------|-------------------|
| 1 | **Author Credibility** | GitHub REST API `/users/{owner}` | Account age, type (user/org), public repos count, followers, profile completeness | Verified org or established account (>2yr, >20 repos) boosts confidence. New/empty account penalizes. |
| 2 | **Repo Vitals** | GitHub REST API `/repos/{owner}/{repo}` | Stars, forks, age (created_at), last push, open issues count | Young repo (<90 days) is a risk multiplier. High stars + young = check velocity. No activity in 6mo = maintenance risk. |
| 3 | **License** | Repo API `license` field + `LICENSE` file | License type, presence, compatibility | No license = caution. Permissive (MIT/Apache/ISC) = neutral. GPL in vendored deps = flag. |
| 4 | **Dependency Lifecycle** | `package.json` scripts field (already parsed) | Pre/post install hooks, prepare scripts, number of deps | Install hooks = critical signal (already ACR-S-018). Dep count >50 = larger attack surface note. |
| 5 | **Install Invasiveness** | Code scan (static patterns) | Files written outside project dir, dotfile modifications, shell RC edits | Modifying `.bashrc`, `.zshrc`, other tool configs = high invasiveness caveat. Count of external paths touched. |

### Tier 2: Medium Signals (at scan time, 1-3s)

| # | Dimension | Data Source | Signal Extracted | Confidence Impact |
|---|-----------|-------------|------------------|-------------------|
| 6 | **Network Behavior** | Code scan (enhanced) | Outbound domains, phone-home patterns, telemetry, localhost bindings, CORS policy | Categorize each call: user-initiated vs background. Phone-home without opt-out = caveat. CORS `*` on localhost = caveat. |
| 7 | **Filesystem Scope** | Code scan (enhanced) | Read/write targets, temp file patterns, symlink handling | Writing only to project dir = good. System-wide writes = caveat. No cleanup = caveat. |
| 8 | **Auth & Access Control** | Code scan (enhanced) | API endpoint auth, CORS headers, sensitive endpoints (kill, browse, exec) | Unauthenticated dangerous endpoints = high-severity caveat. Localhost-only binding = mitigating factor. |
| 9 | **Update Mechanism** | Code scan + repo analysis | Auto-update code, signature verification, checksum validation | Auto-download without verification = caveat. No update mechanism = neutral. |

### Tier 3: Deep Scan (opt-in, 5-15s)

| # | Dimension | Data Source | Signal Extracted | Confidence Impact |
|---|-----------|-------------|------------------|-------------------|
| 10 | **Contributor Concentration** | GitHub API `/repos/{owner}/{repo}/contributors` | Number of contributors, top contributor %, bus factor | Single author = risk note. Top contributor >95% of commits = effectively single-author. |
| 11 | **Star Velocity** | GitHub API (stars with timestamps, or heuristic: stars/age) | Stars per day, organic vs suspicious growth | >50 stars/day on a <30 day repo with few contributors = suspicious gaming signal. |
| 12 | **Known Vulnerabilities** | `npm audit --json` or OSV API against lockfile | CVE count by severity, unpatched vulns | Critical CVEs = strong confidence penalty. All clean = confidence boost. |
| 13 | **Privacy** | Code scan (enhanced) | Source code exposure via endpoints, PII handling, IP leakage | Serving raw source over HTTP = caveat. No PII filtering during indexing = caveat. |
| 14 | **Community Signals** | GitHub API `/repos/{owner}/{repo}/issues` | Security-related issues, responsiveness, release cadence | Open security issues = penalty. Fast response to vuln reports = boost. |

## Confidence Calculation

### Base Confidence (from code scan)

| Condition | Base |
|-----------|------|
| Short-circuit fired (confirmed malicious) | 0.95 |
| ≥2 critical + intent rules | 0.90 |
| ≥3 high findings | 0.80 |
| Zero findings | 0.60 |
| Default | 0.55 |
| ≤2 findings (borderline) | 0.45 |

Key change from v0.1: a clean code scan starts at 0.60 confidence (was 0.90). Metadata is what pushes it higher.

### Metadata Adjustments

Each dimension produces a modifier. Adjustments are additive, then clamped to [0.10, 0.98].

```
confidence = clamp(base + Σ adjustments, 0.10, 0.98)
```

| Signal | Boost | Penalty | Caveat Text |
|--------|-------|---------|-------------|
| Author: verified org or >2yr account | +0.08 | — | — |
| Author: <6mo account, no other repos | — | -0.10 | "Author account is new with no track record" |
| Repo age >1yr | +0.05 | — | — |
| Repo age <90 days | — | -0.08 | "Repository is less than 90 days old" |
| License present + permissive | +0.03 | — | — |
| No license | — | -0.05 | "No license file found" |
| Zero install hooks | +0.03 | — | — |
| Install hooks present | — | -0.05 | "Package has install lifecycle hooks" |
| Low install invasiveness (0-1 external paths) | +0.03 | — | — |
| High install invasiveness (5+ external paths) | — | -0.10 | "Modifies N files outside project directory" |
| Network: all calls to expected domains | +0.05 | — | — |
| Network: phone-home without opt-out | — | -0.07 | "Phones home on startup without opt-out" |
| Network: CORS wildcard on localhost | — | -0.08 | "CORS wildcard (*) on local HTTP server" |
| Auth: dangerous endpoints authenticated | +0.03 | — | — |
| Auth: unauthenticated dangerous endpoints | — | -0.12 | "Unauthenticated endpoint: {name}" |
| Deep: >3 contributors | +0.05 | — | — |
| Deep: single author | — | -0.05 | "Single-author project" |
| Deep: suspicious star velocity | — | -0.10 | "Star growth pattern appears inorganic" |
| Deep: zero known CVEs | +0.05 | — | — |
| Deep: critical CVEs unpatched | — | -0.15 | "N critical CVEs in dependencies" |

### Worked Examples

**stitch-mcp** (legitimate Google DevRel project):
```
Base: 0.60 (clean code scan, 2 low findings)
+ 0.08  author: David East, Google org, established
+ 0.05  repo age: >1yr
+ 0.03  license: Apache-2.0
+ 0.03  zero install hooks
+ 0.03  low invasiveness
+ 0.05  network: all calls to *.googleapis.com
= 0.87 confidence → displays as 87%
Caveats: [] (none)
```

**C-based knowledge graph MCP** (legitimate but young + risky surface):
```
Base: 0.60 (clean code scan)
- 0.08  repo age: <90 days (created 2026-02-24)
- 0.05  single author (essentially)
- 0.08  CORS wildcard on localhost
- 0.12  unauthenticated /api/process-kill endpoint
- 0.07  phones home on startup (GitHub API check)
- 0.10  high install invasiveness (10+ dotfiles)
+ 0.03  license: MIT
+ 0.03  zero install hooks (C project, no npm)
= 0.16 confidence → displays as 16%
Caveats: [6 items]
Verdict: CONDITIONAL PASS (code clean but low confidence)
```

## New Data Types

```typescript
interface MetadataSignals {
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

interface Caveat {
  dimension: string;     // e.g. "repo_age", "cors_policy"
  severity: "info" | "warning" | "critical";
  text: string;          // human-readable
}

// Extended verdict type
type Verdict = "SAFE" | "CONDITIONAL_PASS" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";
```

## New Files

```
src/
├── engine/
│   └── confidence.ts          # New confidence calculator (replaces calculateVerdictConfidence)
├── lib/
│   ├── github-metadata.ts     # GitHub API fetcher (Tier 1 + 2 signals)
│   ├── deep-scanner.ts        # Tier 3 opt-in analysis (CVEs, contributors, star velocity)
│   └── metadata-extractors.ts # Extract network/filesystem/auth signals from code scan results
```

## Verdict Display Logic

```
score >= 80 AND confidence >= 0.70  → SAFE
score >= 80 AND confidence < 0.70   → CONDITIONAL PASS
score >= 50                         → CAUTION
score >= 20                         → SUSPICIOUS
score < 20                          → DANGEROUS
```

## UI Changes

Verdict banner gains a second line for confidence and a caveats section:

```
┌─────────────────────────────────────────────────┐
│  🟢 SAFE                                        │
│  Score: 90/100 · Confidence: 87% · 2 findings   │
│  200 files · 42 rules · 1.2s                     │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  🟡 CONDITIONAL PASS                             │
│  Score: 92/100 · Confidence: 16% · 0 findings   │
│  156 files · 42 rules · 0.9s                     │
│                                                  │
│  ⚠ Repo is less than 90 days old                │
│  ⚠ CORS wildcard (*) on local HTTP server       │
│  ⚠ Unauthenticated endpoint: /api/process-kill  │
│  ⚠ Phones home on startup without opt-out       │
│  ⚠ Modifies 10+ files outside project directory │
│  ⚠ Single-author project                        │
└─────────────────────────────────────────────────┘
```

GitHub Repo scan mode gets a toggle: `☐ Deep scan (slower, checks CVEs + contributor patterns)`.

Paste/Upload mode is unchanged — metadata dimensions only apply when a GitHub URL is provided.

## Gap Analysis: Current AC Coverage vs. Framework

| Dimension | v0.1 Coverage | Phase 2 Adds |
|-----------|--------------|--------------|
| 1. Author credibility | None | GitHub API user profile |
| 2. Repo vitals | None | GitHub API repo metadata |
| 3. License | None | License field parsing |
| 4. Dependency lifecycle | ACR-S-018 (install hooks) | Dep count, hook categorization |
| 5. Install invasiveness | None | Static pattern extraction |
| 6. Network behavior | ACR-S-005/020 (patterns) | Domain categorization, CORS, phone-home detection |
| 7. Filesystem scope | ACR-S-012 (path traversal) | Write target classification |
| 8. Auth & access control | ACR-S-026 (unsafe localhost) | Endpoint auth assessment |
| 9. Update mechanism | None | Auto-update pattern detection |
| 10. Contributor concentration | None | GitHub API (deep scan) |
| 11. Star velocity | None | Stars/age heuristic (deep scan) |
| 12. Known vulnerabilities | None | npm audit / OSV API (deep scan) |
| 13. Privacy | None | Enhanced code patterns (deep scan) |
| 14. Community signals | None | GitHub API issues (deep scan) |

## Provenance

This framework was derived from:
- Manual security audits of `davideast/stitch-mcp` and a C-based MCP knowledge graph server
- Comparison of audit methodologies between AgentCanary's automated scanning and comprehensive manual review
- The observation that AC's 50% confidence on clean repos stems from missing metadata context
