# AgentCanary Benchmark Report

**Generated:** 2026-03-20 11:24
**Total repos scanned:** 294

## Overall Agreement

| Metric | Value |
|--------|-------|
| Errors/skipped | 294 |
| **Agreement rate** | **0%** |

## AC Verdict Distribution

| Verdict | Count |
|---------|-------|
| SAFE | 213 |
| CAUTION | 53 |
| DANGEROUS | 21 |
| SUSPICIOUS | 2 |

## Detection Accuracy by Category

### SAFE repos (114 total)
- AC says SAFE: 86
- AC says CAUTION: 16
- AC says DANGEROUS: 11 ← false positives
- Errors: 1
- **True negative rate: 90%**
- **False positive rate: 10%**

### SUSPICIOUS repos (23 total)
- AC says DANGEROUS: 4
- AC says CAUTION: 4
- AC says SAFE: 14 ← false negatives
- Errors: 0
- **Detection rate: 35%**
- **False negative rate: 61%**

### UNKNOWN repos (157 total)
- AC says SAFE: 113
- AC says CAUTION: 33
- AC says DANGEROUS: 6
- Errors: 4

## Timing

| | AC | Claude |
|---|---|---|
| Median | 992ms | 0ms |
| Min | 623ms | N/Ams |
| Max | 27858ms | N/Ams |

## Score Distribution

| Category | Min | Median | Max | Avg |
|---|---|---|---|---|
| SAFE | 0 | 96 | 100 | 81 |
| SUSPICIOUS | 0 | 84 | 100 | 71 |

## False Negatives (CRITICAL — missed threats)

| Repo | AC Verdict | AC Score | Claude Verdict |
|------|-----------|----------|----------------|
| https://github.com/kenhuangus/mcp-vulnerable-server-demo | SAFE | 100 | SKIP |
| https://github.com/angrypenguinpng/big-brother-mcp | SAFE | 100 | SKIP |
| https://github.com/appsecco/vulnerable-mcp-servers-lab | SAFE | 90 | SKIP |
| https://github.com/ramkansal/pentestMCP | SAFE | 84 | SKIP |
| https://github.com/LayeSec006/pentest-mcp-server | SAFE | 99 | SKIP |
| https://github.com/Sim-xia/Blind-Auditor | SAFE | 100 | SKIP |
| https://github.com/Operative-Sh/web-eval-agent | SAFE | 100 | SKIP |
| https://github.com/maxim-saplin/mcp_safe_local_python_executor | SAFE | 100 | SKIP |
| https://github.com/MladenSU/cli-mcp-server | SAFE | 84 | SKIP |
| https://github.com/misiektoja/kill-process-mcp | SAFE | 100 | SKIP |
| https://github.com/antonio-mello-ai/mcp-pfsense | SAFE | 93 | SKIP |
| https://github.com/antonio-mello-ai/mcp-proxmox | SAFE | 97 | SKIP |
| https://github.com/carterlasalle/mac_messages_mcp | SAFE | 84 | SKIP |
| https://github.com/FradSer/mcp-server-apple-reminders | SAFE | 90 | SKIP |

## False Positives (safe repos flagged DANGEROUS)

| Repo | AC Score | AC Findings |
|------|----------|-------------|
| https://github.com/anthropics/skills | 0 | 2 |
| https://github.com/anthropics/claude-plugins-official | 0 | 9 |
| https://github.com/trailofbits/skills | 0 | 12 |
| https://github.com/cisco-ai-defense/mcp-scanner | 0 | 102 |
| https://github.com/epiral/bb-browser | 0 | 12 |
| https://github.com/concierge-hq/concierge | 0 | 2 |
| https://github.com/affaan-m/everything-claude-code | 0 | 21 |
| https://github.com/alirezarezvani/claude-skills | 0 | 11 |
| https://github.com/antgroup/MCPScan | 0 | 5 |
| https://github.com/apisec-inc/mcp-audit | 0 | 11 |
| https://github.com/HeadyZhang/agent-audit | 0 | 31 |

## Success Criteria Check

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Agreement rate (±1 level) | > 75% | 0% | FAIL |
| False negative rate | < 5% | 61% | FAIL |
| False positive rate | < 20% | 10% | PASS |
| Detection rate (SUSPICIOUS) | > 80% | 35% | FAIL |
| Median AC scan time | < 5000ms | 992ms | PASS |

