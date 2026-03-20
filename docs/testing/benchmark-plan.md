# AgentCanary Engine Benchmark — Testing Plan

> **Goal:** Run 294 GitHub repos through both AgentCanary (AC) and Claude (direct LLM analysis) in parallel, compare verdicts, and measure AC's detection accuracy.

## Test Dataset

**Source:** `/tmp/ac-test-repos.txt` (294 repos, 12 sections)

| Category | Count | Expected AC Verdict |
|----------|-------|-------------------|
| SAFE | 114 | SAFE or CONDITIONAL_PASS |
| UNKNOWN | 157 | Any — ground truth unknown |
| SUSPICIOUS | 23 | CAUTION or DANGEROUS |

Includes official MCP SDKs, major company servers (AWS, Google, Microsoft), community repos, and known-malicious PoCs (exploit demos, honeypots, intentionally vulnerable servers).

## Architecture

```
scripts/benchmark-run.sh
  ├── Parse repo list (skip comments/blanks)
  ├── For each repo (5 concurrent):
  │   ├── AC: curl POST localhost:3000/api/scan/github
  │   └── Claude: claude CLI with structured audit prompt
  │
  ├── Save per-repo results:
  │   ├── results/ac/{owner}__{repo}.json
  │   └── results/claude/{owner}__{repo}.json
  │
  └── Append to results/benchmark-data.csv

scripts/benchmark-compare.sh results/
  └── Generates results/benchmark-report.md
```

## Execution Steps

### 1. Pre-flight (5 min)

```bash
# Ensure AC server is running
curl -sf http://localhost:3000/api/scan/github \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com/modelcontextprotocol/servers"}' | jq '.verdict'

# Ensure claude CLI works
echo "Say OK" | claude --print

# Ensure GITHUB_TOKEN is set (avoid 60 req/hr unauthenticated limit)
echo "GITHUB_TOKEN set: $([ -n "$GITHUB_TOKEN" ] && echo YES || echo NO)"

# Create results dirs
mkdir -p results/{ac,claude}
```

### 2. Run benchmark (~2-3 hours)

```bash
cd /Users/muellah/_muellah/AI/Claude/AgentCanary
./scripts/benchmark-run.sh /tmp/ac-test-repos.txt
```

### 3. Generate comparison report

```bash
./scripts/benchmark-compare.sh results/
# Output: results/benchmark-report.md
```

## Claude Baseline Prompt

Standardized prompt producing structured JSON for easy comparison:

```
You are a security auditor for MCP servers and AI agent tools.
Analyze the GitHub repository at {URL}.

Return ONLY valid JSON:
{
  "verdict": "SAFE" | "CAUTION" | "DANGEROUS",
  "score": <0-100, where 100=perfectly safe>,
  "confidence": <0.0-1.0>,
  "key_concerns": ["..."],
  "positive_signals": ["..."],
  "summary": "one paragraph"
}

Focus on: credential access, data exfiltration, command injection,
path traversal, network behavior, obfuscated code, auth issues,
privilege escalation. Be conservative — flag real risks, not style issues.
```

## Comparison Metrics

### Per-repo
| Field | Description |
|-------|------------|
| `verdict_match` | AC == Claude (CONDITIONAL_PASS mapped to SAFE) |
| `direction_match` | Both agree: safe (SAFE/CONDITIONAL_PASS) vs risky (CAUTION/DANGEROUS) |
| `ac_time_ms` | AC scan duration |
| `claude_time_ms` | Claude response duration |
| `score_delta` | abs(ac_score - claude_score) |

### Aggregate
| Metric | Formula |
|--------|---------|
| **True positive rate** | SUSPICIOUS repos flagged CAUTION/DANGEROUS by AC |
| **True negative rate** | SAFE repos rated SAFE by AC |
| **False positive rate** | SAFE repos flagged CAUTION/DANGEROUS by AC |
| **False negative rate** | SUSPICIOUS repos rated SAFE by AC |
| **Agreement rate** | % where AC and Claude give same direction |
| **Speed ratio** | median(ac_time) / median(claude_time) |

### Confusion Matrix
```
                    AC: SAFE    AC: CAUTION    AC: DANGEROUS
Claude: SAFE          ✓            FP-mild       FP-severe
Claude: CAUTION      FN-mild        ✓            FP-mild
Claude: DANGEROUS    FN-severe     FN-mild         ✓
```

## Rate Limiting & Cost

| Resource | Limit | Impact |
|----------|-------|--------|
| GitHub API (with token) | 5,000 req/hr | AC uses ~3-5 calls/repo → ~70 repos/hr |
| GitHub API (no token) | 60 req/hr | Unusable — TOKEN required |
| Claude CLI | ~3 concurrent | ~$0.01-0.03/repo → ~$3-9 total |
| AC concurrent scans | 5 | Bottleneck is git clone I/O |
| **Estimated total** | | **~2-3 hours, ~$5-8 Claude cost** |

## Error Handling

- Clone failures → `CLONE_ERROR`, skipped, logged
- Claude API timeouts (>90s) → `TIMEOUT`, skipped, logged
- AC scan errors → `SCAN_ERROR`, skipped, logged
- Rate limit hits → exponential backoff (2s, 4s, 8s, 16s)
- Progress saved after each repo (resume-safe)

## Success Criteria

| Metric | Target | Notes |
|--------|--------|-------|
| Agreement rate (±1 level) | > 75% | AC and Claude same direction |
| False negative rate (missed DANGEROUS) | < 5% | Critical — safety matters |
| False positive rate on SAFE repos | < 20% | Some over-flagging is OK for MVP |
| True positive rate on SUSPICIOUS | > 80% | Must catch known-bad repos |
| Median AC scan time | < 5s | Excluding clone time |

## Key Questions to Answer

1. **Does AC catch what Claude catches?** Missed detections → new rules needed
2. **Is AC too noisy?** High FP rate → rule tuning or confidence adjustment
3. **How does confidence scoring perform?** UNKNOWN repos should get lower confidence
4. **What's the score distribution?** Histogram of scores by category
5. **Which rule IDs fire most?** Identify noisy vs useful rules
6. **What does Claude find that AC misses?** Gap analysis → rule backlog

## Non-Goals (this round)

- Upload/paste mode testing (separate test)
- Dynamic analysis or fuzzing
- Performance under load
- UI/UX testing
- Deep scan (Tier 3) metadata — only quick metadata
