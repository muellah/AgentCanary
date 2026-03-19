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

## IMPORTANT: Rotate Your API Key

You pasted your Anthropic API key in the chat. Go to:
https://console.anthropic.com/settings/keys
1. Delete the compromised key
2. Create a new one
3. Update .env.local: `echo "ANTHROPIC_API_KEY=your-new-key" > .env.local`
