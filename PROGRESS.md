# AgentCanary MVP — Build Progress

## Status: BUILD COMPLETE

**When you wake up, run:**
```bash
cd /Users/muellah/_muellah/AI/Claude/AgentCanary
npm run dev
```
Then open **http://localhost:3000**

---

## What Was Built

### Project Structure
```
AgentCanary/
├── src/
│   ├── engine/                  # Pure TypeScript engine (zero web deps)
│   │   ├── types.ts             # All type definitions
│   │   ├── rule-loader.ts       # YAML rule parser + indexer
│   │   ├── scanner.ts           # 4-phase scan pipeline orchestrator
│   │   ├── sarif-formatter.ts   # SARIF v2.1.0 output
│   │   ├── checkers/
│   │   │   ├── static.ts        # Regex + string pattern matching
│   │   │   ├── heuristic.ts     # Statistical anomaly detection
│   │   │   ├── semantic.ts      # LLM-powered analysis (Claude API)
│   │   │   └── composite.ts     # Multi-rule convergence detection
│   │   └── index.ts
│   │
│   ├── lib/                     # Server-side business logic
│   │   ├── github-fetcher.ts    # Clone GitHub repos (shallow, temp dir)
│   │   ├── file-walker.ts       # Walk directories, extract scannable files
│   │   ├── rule-registry.ts     # Load + cache all 36 YAML rules
│   │   ├── claude-api.ts        # Anthropic SDK integration
│   │   └── scan-orchestrator.ts # Coordinates full scan workflows
│   │
│   ├── rules/                   # 36 ACR detection rules
│   │   ├── static/              # 24 rules (regex patterns)
│   │   ├── heuristic/           # 2 rules (anomaly detection)
│   │   ├── semantic/            # 7 rules (LLM-powered)
│   │   └── composite/           # 3 rules (convergence)
│   │
│   └── app/                     # Next.js frontend + API
│       ├── layout.tsx           # Dark theme, Tailwind
│       ├── page.tsx             # Main UI (scan form + results)
│       ├── globals.css
│       └── api/
│           └── scan/
│               ├── github/route.ts  # POST /api/scan/github
│               └── file/route.ts    # POST /api/scan/file
│
├── .env.local                   # ANTHROPIC_API_KEY (rotate this!)
├── package.json
├── tsconfig.json
├── next.config.ts
├── postcss.config.mjs
└── .gitignore
```

### What Works
- **GitHub Repo Scanning**: Paste a URL → clones repo → walks files → runs all rules → shows verdict
- **Paste/Upload Scanning**: Paste code/SKILL.md → runs all rules → shows verdict
- **36 Detection Rules**: All loaded from YAML, covering 16 attack vectors
- **4-Phase Pipeline**: Static → Heuristic → Semantic (Claude API) → Composite
- **Dark Theme UI**: With verdict banners (SAFE/CAUTION/SUSPICIOUS/DANGEROUS)
- **"Load malicious example" button**: Pre-loads the real ToxicSkills clawhub sample
- **SARIF Output**: Generated for every scan (available in API response)
- **Claude API Integration**: Semantic rules use Claude Sonnet for analysis

### Build Verification
- `npm run build` — passes with zero errors
- Dev server boots in 292ms
- All TypeScript types check clean

## Decisions Made While You Slept

1. **Manual Next.js setup** (not create-next-app) — the interactive installer was blocking in non-TTY mode
2. **Tailwind v4** with `@tailwindcss/postcss` — latest version, simple config
3. **simple-git** for cloning — listed in `serverExternalPackages` to avoid bundling issues
4. **Shallow clone** (`--depth 1`) for speed — no need for full git history
5. **Max 200 files per repo scan** — prevents DoS on huge repos
6. **Max 512KB per file** — skips enormous files
7. **Claude Sonnet** as default semantic model — best balance of quality/speed/cost
8. **Worst-file-wins** for aggregate verdict — if any file is DANGEROUS, the whole repo is DANGEROUS

## Known Limitations (MVP scope)

1. **No file upload** — paste only for now (file upload UI is easy to add)
2. **No MCP server connection** — GitHub + paste only (MCP SDK integration is researched and ready)
3. **No canary token system** — designed but not implemented yet
4. **No caching** — each scan re-loads rules (fast enough for now)
5. **Semantic rules need API key** — will gracefully skip if no key set
6. **No progress streaming** — scan completes then shows all results at once
7. **No metadata/context signals** — code-only analysis, no GitHub API metadata (see Phase 2)
8. **No CVE checking** — dependencies not audited against vulnerability databases
9. **No CONDITIONAL PASS verdict** — can't express "code is clean but context is concerning"

---

## Phase 2: Metadata Context Layer (Designed, Not Yet Built)

**Spec:** `docs/superpowers/specs/2026-03-20-mcp-repo-safety-framework-design.md`

### What It Adds

A 14-dimension MCP Repo Safety Assessment Framework that runs alongside the existing code scanner. Metadata signals feed into the confidence score (not the code score), enabling verdicts like CONDITIONAL PASS — "code looks clean but context warrants caution."

### New Capabilities

- **GitHub API integration** — author credibility, repo vitals, license, contributor concentration
- **Confidence-as-context** — clean code scan starts at 60% confidence; metadata pushes it to 85%+ (or down to 16%)
- **Caveats system** — human-readable context notes ("repo < 90 days old", "CORS wildcard on localhost")
- **CONDITIONAL PASS verdict** — score >= 80 but confidence < 70%
- **Deep scan mode** — opt-in CVE audit, star velocity analysis, contributor concentration
- **Enhanced code extractors** — network behavior classification, filesystem scope, auth assessment

### New Files (Planned)

```
src/
├── engine/
│   └── confidence.ts          # New confidence calculator
├── lib/
│   ├── github-metadata.ts     # GitHub API fetcher (Tier 1+2)
│   ├── deep-scanner.ts        # Tier 3 opt-in analysis
│   └── metadata-extractors.ts # Extract network/filesystem/auth signals from code
```

### Three Tiers

1. **Quick signals (<1s)** — author profile, repo age/stars, license, dep lifecycle, install invasiveness
2. **Medium signals (1-3s)** — network behavior classification, filesystem scope, auth assessment, update mechanism
3. **Deep scan (opt-in, 5-15s)** — contributor concentration, star velocity, CVE audit, privacy, community signals

## IMPORTANT: Rotate Your API Key

You pasted your Anthropic API key in the chat. Go to:
https://console.anthropic.com/settings/keys
1. Delete the compromised key
2. Create a new one
3. Update .env.local: `echo "ANTHROPIC_API_KEY=your-new-key" > .env.local`
