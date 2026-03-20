#!/bin/bash
# AgentCanary Benchmark Comparison Report Generator
# Usage: ./scripts/benchmark-compare.sh results/20260321_123456/
#
# Reads benchmark-data.csv and generates benchmark-report.md

set -euo pipefail

RESULTS_DIR="${1:?Usage: $0 <results-dir>}"
CSV_FILE="$RESULTS_DIR/benchmark-data.csv"
REPORT="$RESULTS_DIR/benchmark-report.md"

if [[ ! -f "$CSV_FILE" ]]; then
  echo "ERROR: $CSV_FILE not found"
  exit 1
fi

echo "Generating benchmark report from $CSV_FILE..."

python3 << 'PYTHON_SCRIPT' - "$CSV_FILE" "$REPORT"
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime

csv_file = sys.argv[1]
report_file = sys.argv[2]

rows = []
with open(csv_file) as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Strip quotes from values
        row = {k: v.strip('"') for k, v in row.items()}
        rows.append(row)

total = len(rows)
if total == 0:
    print("No data found")
    sys.exit(1)

# ---- Category breakdown ----
by_category = defaultdict(list)
for r in rows:
    by_category[r['category']].append(r)

# ---- Agreement stats ----
agreements = Counter(r['agreement'] for r in rows)
match = agreements.get('MATCH', 0)
close = agreements.get('CLOSE', 0)
disagree = agreements.get('DISAGREE', 0)
errors = agreements.get('ERROR', 0) + agreements.get('N/A', 0)
compared = match + close + disagree
agreement_pct = ((match + close) / compared * 100) if compared > 0 else 0

# ---- Verdict distributions ----
ac_verdicts = Counter(r['ac_verdict'] for r in rows if r['ac_verdict'] != 'ERROR')
cl_verdicts = Counter(r['claude_verdict'] for r in rows if r['claude_verdict'] not in ('ERROR', 'SKIP'))

# ---- Category accuracy ----
def calc_category_stats(cat_rows, expected_safe=True):
    if not cat_rows:
        return {}
    ac_safe = sum(1 for r in cat_rows if r['ac_verdict'] in ('SAFE', 'CONDITIONAL_PASS'))
    ac_caution = sum(1 for r in cat_rows if r['ac_verdict'] == 'CAUTION')
    ac_dangerous = sum(1 for r in cat_rows if r['ac_verdict'] == 'DANGEROUS')
    ac_error = sum(1 for r in cat_rows if r['ac_verdict'] == 'ERROR')
    total_cat = len(cat_rows)

    if expected_safe:
        correct = ac_safe + ac_caution  # CAUTION on safe is acceptable
        fp = ac_dangerous
        rate = correct / (total_cat - ac_error) * 100 if (total_cat - ac_error) > 0 else 0
    else:
        correct = ac_caution + ac_dangerous
        fn = ac_safe
        rate = correct / (total_cat - ac_error) * 100 if (total_cat - ac_error) > 0 else 0

    return {
        'total': total_cat,
        'safe': ac_safe,
        'caution': ac_caution,
        'dangerous': ac_dangerous,
        'error': ac_error,
        'correct': correct,
        'rate': rate
    }

safe_stats = calc_category_stats(by_category.get('SAFE', []), expected_safe=True)
suspicious_stats = calc_category_stats(by_category.get('SUSPICIOUS', []), expected_safe=False)
unknown_stats = calc_category_stats(by_category.get('UNKNOWN', []), expected_safe=True)  # direction unknown

# ---- Timing stats ----
ac_times = [int(r['ac_time_ms']) for r in rows if r['ac_time_ms'].isdigit() and int(r['ac_time_ms']) > 0]
cl_times = [int(r.get('claude_time_ms', '0') or '0') for r in rows
            if r.get('claude_time_ms', '0').isdigit() and int(r.get('claude_time_ms', '0')) > 0]

def median(lst):
    if not lst:
        return 0
    s = sorted(lst)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) // 2

# ---- Score distributions ----
ac_scores_safe = [int(r['ac_score']) for r in by_category.get('SAFE', [])
                  if r['ac_score'].isdigit()]
ac_scores_suspicious = [int(r['ac_score']) for r in by_category.get('SUSPICIOUS', [])
                        if r['ac_score'].isdigit()]

# ---- Disagreements ----
disagreements = [r for r in rows if r['agreement'] == 'DISAGREE']

# ---- False negatives (SUSPICIOUS repos AC says SAFE) ----
false_negatives = [r for r in by_category.get('SUSPICIOUS', [])
                   if r['ac_verdict'] in ('SAFE', 'CONDITIONAL_PASS')]

# ---- False positives (SAFE repos AC says DANGEROUS) ----
false_positives = [r for r in by_category.get('SAFE', [])
                   if r['ac_verdict'] == 'DANGEROUS']

# ---- Generate report ----
with open(report_file, 'w') as f:
    f.write(f"# AgentCanary Benchmark Report\n\n")
    f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    f.write(f"**Total repos scanned:** {total}\n\n")

    f.write("## Overall Agreement\n\n")
    f.write(f"| Metric | Value |\n")
    f.write(f"|--------|-------|\n")
    f.write(f"| Exact match | {match} ({match/compared*100:.0f}%) |\n" if compared else "")
    f.write(f"| Close (±1 level) | {close} ({close/compared*100:.0f}%) |\n" if compared else "")
    f.write(f"| Disagree | {disagree} ({disagree/compared*100:.0f}%) |\n" if compared else "")
    f.write(f"| Errors/skipped | {errors} |\n")
    f.write(f"| **Agreement rate** | **{agreement_pct:.0f}%** |\n\n")

    f.write("## AC Verdict Distribution\n\n")
    f.write("| Verdict | Count |\n|---------|-------|\n")
    for v, c in ac_verdicts.most_common():
        f.write(f"| {v} | {c} |\n")
    f.write("\n")

    f.write("## Detection Accuracy by Category\n\n")

    if safe_stats:
        f.write(f"### SAFE repos ({safe_stats['total']} total)\n")
        f.write(f"- AC says SAFE: {safe_stats['safe']}\n")
        f.write(f"- AC says CAUTION: {safe_stats['caution']}\n")
        f.write(f"- AC says DANGEROUS: {safe_stats['dangerous']} ← false positives\n")
        f.write(f"- Errors: {safe_stats['error']}\n")
        f.write(f"- **True negative rate: {safe_stats['rate']:.0f}%**\n")
        fp_rate = safe_stats['dangerous'] / (safe_stats['total'] - safe_stats['error']) * 100 if (safe_stats['total'] - safe_stats['error']) > 0 else 0
        f.write(f"- **False positive rate: {fp_rate:.0f}%**\n\n")

    if suspicious_stats:
        f.write(f"### SUSPICIOUS repos ({suspicious_stats['total']} total)\n")
        f.write(f"- AC says DANGEROUS: {suspicious_stats['dangerous']}\n")
        f.write(f"- AC says CAUTION: {suspicious_stats['caution']}\n")
        f.write(f"- AC says SAFE: {suspicious_stats['safe']} ← false negatives\n")
        f.write(f"- Errors: {suspicious_stats['error']}\n")
        f.write(f"- **Detection rate: {suspicious_stats['rate']:.0f}%**\n")
        fn_rate = suspicious_stats['safe'] / (suspicious_stats['total'] - suspicious_stats['error']) * 100 if (suspicious_stats['total'] - suspicious_stats['error']) > 0 else 0
        f.write(f"- **False negative rate: {fn_rate:.0f}%**\n\n")

    if unknown_stats:
        f.write(f"### UNKNOWN repos ({unknown_stats['total']} total)\n")
        f.write(f"- AC says SAFE: {unknown_stats['safe']}\n")
        f.write(f"- AC says CAUTION: {unknown_stats['caution']}\n")
        f.write(f"- AC says DANGEROUS: {unknown_stats['dangerous']}\n")
        f.write(f"- Errors: {unknown_stats['error']}\n\n")

    f.write("## Timing\n\n")
    f.write(f"| | AC | Claude |\n|---|---|---|\n")
    f.write(f"| Median | {median(ac_times)}ms | {median(cl_times)}ms |\n")
    if ac_times:
        f.write(f"| Min | {min(ac_times)}ms | {min(cl_times) if cl_times else 'N/A'}ms |\n")
        f.write(f"| Max | {max(ac_times)}ms | {max(cl_times) if cl_times else 'N/A'}ms |\n")
    if ac_times and cl_times:
        ratio = median(ac_times) / median(cl_times) if median(cl_times) > 0 else 0
        f.write(f"| **Speed ratio** | **{ratio:.1f}x** | 1.0x |\n")
    f.write("\n")

    if ac_scores_safe:
        f.write("## Score Distribution\n\n")
        f.write(f"| Category | Min | Median | Max | Avg |\n|---|---|---|---|---|\n")
        f.write(f"| SAFE | {min(ac_scores_safe)} | {median(ac_scores_safe)} | {max(ac_scores_safe)} | {sum(ac_scores_safe)//len(ac_scores_safe)} |\n")
        if ac_scores_suspicious:
            f.write(f"| SUSPICIOUS | {min(ac_scores_suspicious)} | {median(ac_scores_suspicious)} | {max(ac_scores_suspicious)} | {sum(ac_scores_suspicious)//len(ac_scores_suspicious)} |\n")
        f.write("\n")

    if false_negatives:
        f.write("## False Negatives (CRITICAL — missed threats)\n\n")
        f.write("| Repo | AC Verdict | AC Score | Claude Verdict |\n|------|-----------|----------|----------------|\n")
        for r in false_negatives:
            f.write(f"| {r['url']} | {r['ac_verdict']} | {r['ac_score']} | {r['claude_verdict']} |\n")
        f.write("\n")

    if false_positives:
        f.write("## False Positives (safe repos flagged DANGEROUS)\n\n")
        f.write("| Repo | AC Score | AC Findings |\n|------|----------|-------------|\n")
        for r in false_positives:
            f.write(f"| {r['url']} | {r['ac_score']} | {r['ac_findings']} |\n")
        f.write("\n")

    if disagreements:
        f.write("## Disagreements (AC vs Claude)\n\n")
        f.write("| Repo | Category | AC | Claude |\n|------|----------|-------|--------|\n")
        for r in disagreements[:30]:  # Top 30
            f.write(f"| {r['url'].split('/')[-1]} | {r['category']} | {r['ac_verdict']}({r['ac_score']}) | {r['claude_verdict']}({r.get('claude_score','?')}) |\n")
        if len(disagreements) > 30:
            f.write(f"\n*...and {len(disagreements) - 30} more disagreements*\n")
        f.write("\n")

    # Success criteria check
    f.write("## Success Criteria Check\n\n")
    f.write("| Metric | Target | Actual | Status |\n|--------|--------|--------|--------|\n")
    f.write(f"| Agreement rate (±1 level) | > 75% | {agreement_pct:.0f}% | {'PASS' if agreement_pct > 75 else 'FAIL'} |\n")
    if suspicious_stats and suspicious_stats['total'] > suspicious_stats['error']:
        fn_rate_val = suspicious_stats['safe'] / (suspicious_stats['total'] - suspicious_stats['error']) * 100
        f.write(f"| False negative rate | < 5% | {fn_rate_val:.0f}% | {'PASS' if fn_rate_val < 5 else 'FAIL'} |\n")
    if safe_stats and safe_stats['total'] > safe_stats['error']:
        fp_rate_val = safe_stats['dangerous'] / (safe_stats['total'] - safe_stats['error']) * 100
        f.write(f"| False positive rate | < 20% | {fp_rate_val:.0f}% | {'PASS' if fp_rate_val < 20 else 'FAIL'} |\n")
    if suspicious_stats:
        f.write(f"| Detection rate (SUSPICIOUS) | > 80% | {suspicious_stats['rate']:.0f}% | {'PASS' if suspicious_stats['rate'] > 80 else 'FAIL'} |\n")
    if ac_times:
        med = median(ac_times)
        f.write(f"| Median AC scan time | < 5000ms | {med}ms | {'PASS' if med < 5000 else 'FAIL'} |\n")
    f.write("\n")

print(f"Report written to {report_file}")
print(f"Total rows: {total}")
print(f"Agreement: {agreement_pct:.0f}% ({match} exact + {close} close / {compared} compared)")
PYTHON_SCRIPT

echo ""
echo "Report: $REPORT"
