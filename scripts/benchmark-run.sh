#!/bin/bash
# AgentCanary Benchmark Runner
# Runs repos through both AC engine and Claude baseline, saves results for comparison
# Usage: ./scripts/benchmark-run.sh /tmp/ac-test-repos.txt [--ac-only] [--claude-only] [--limit N]
#
# Requires:
#   - AC dev server running on localhost:3000
#   - claude CLI available in PATH
#   - GITHUB_TOKEN set (for rate limiting)

set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:$PATH"

REPO_LIST="${1:?Usage: $0 <repo-list.txt> [--ac-only|--claude-only] [--limit N]}"
AC_ONLY=false
CLAUDE_ONLY=false
LIMIT=0
CONCURRENCY=5
DELAY=2

shift
LIMIT_NEXT=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ac-only) AC_ONLY=true ;;
    --claude-only) CLAUDE_ONLY=true ;;
    --limit) LIMIT_NEXT=true ;;
    [0-9]*) [[ "$LIMIT_NEXT" == "true" ]] && LIMIT="$1" && LIMIT_NEXT=false ;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results/$TIMESTAMP"
AC_DIR="$RESULTS_DIR/ac"
CLAUDE_DIR="$RESULTS_DIR/claude"
CSV_FILE="$RESULTS_DIR/benchmark-data.csv"
ERROR_LOG="$RESULTS_DIR/errors.log"
PROGRESS_FILE="$RESULTS_DIR/progress.txt"

mkdir -p "$AC_DIR" "$CLAUDE_DIR"

# CSV header
echo "url,category,ac_verdict,ac_score,ac_confidence,ac_findings,ac_time_ms,claude_verdict,claude_score,claude_confidence,claude_concerns,agreement" > "$CSV_FILE"

echo "=========================================="
echo "AgentCanary Benchmark Runner"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="

# ---- Pre-flight ----
echo ""
echo "Pre-flight checks..."

if [[ "$AC_ONLY" != "true" ]] && [[ "$CLAUDE_ONLY" != "true" ]] || [[ "$AC_ONLY" == "true" ]]; then
  if ! curl -sf http://localhost:3000 > /dev/null 2>&1; then
    echo "FAIL: AC server not running on localhost:3000"
    exit 1
  fi
  echo "  AC server: OK"
fi

if [[ "$AC_ONLY" != "true" ]]; then
  if ! command -v claude &>/dev/null; then
    echo "FAIL: claude CLI not found"
    exit 1
  fi
  echo "  Claude CLI: OK"
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "  WARNING: GITHUB_TOKEN not set — rate limiting will be severe (60 req/hr)"
else
  echo "  GitHub token: OK"
fi

# ---- Parse repo list ----
REPOS=()
CATEGORIES=()
DESCRIPTIONS=()

while IFS='|' read -r category url desc; do
  # Skip comments and blank lines
  [[ "$category" =~ ^#.*$ || -z "$category" ]] && continue
  category=$(echo "$category" | xargs)
  url=$(echo "$url" | xargs)
  desc=$(echo "${desc:-}" | xargs)
  [[ -z "$url" ]] && continue
  REPOS+=("$url")
  CATEGORIES+=("$category")
  DESCRIPTIONS+=("$desc")
done < "$REPO_LIST"

TOTAL=${#REPOS[@]}
if [[ "$LIMIT" -gt 0 && "$LIMIT" -lt "$TOTAL" ]]; then
  TOTAL=$LIMIT
fi

echo ""
echo "Repos to scan: $TOTAL"
echo "Results dir: $RESULTS_DIR"
echo ""

# ---- Claude audit prompt ----
CLAUDE_PROMPT='You are a security auditor for MCP servers and AI agent tools.
Analyze the GitHub repository at the URL below for security risks.

Return ONLY valid JSON with this exact structure (no markdown, no code fences):
{"verdict":"SAFE or CAUTION or DANGEROUS","score":0-100,"confidence":0.0-1.0,"key_concerns":["..."],"positive_signals":["..."],"summary":"one paragraph"}

Score: 100=perfectly safe, 0=confirmed malicious.
Focus on: credential access, data exfiltration, command injection, path traversal,
network behavior, obfuscated code, auth issues, privilege escalation.
Be conservative — flag real risks, not style issues.

Repository: '

# ---- Scan function: AC ----
scan_ac() {
  local url="$1"
  local safe_name="$2"
  local start_ms=$(python3 -c "import time; print(int(time.time()*1000))")

  local response
  response=$(curl -sf -m 180 -X POST "http://localhost:3000/api/scan/github" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"$url\"}" 2>&1) || {
    echo "{\"error\":\"curl_failed\",\"raw\":\"$response\"}" > "$AC_DIR/${safe_name}.json"
    echo "SCAN_ERROR|$url|curl failed" >> "$ERROR_LOG"
    echo "ERROR|||0"
    return
  }

  local end_ms=$(python3 -c "import time; print(int(time.time()*1000))")
  local duration=$((end_ms - start_ms))

  echo "$response" > "$AC_DIR/${safe_name}.json"

  # Extract fields
  local verdict score confidence findings
  verdict=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateVerdict',d.get('verdict','ERROR')))" 2>/dev/null || echo "ERROR")
  score=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateScore',d.get('score','?')))" 2>/dev/null || echo "?")
  confidence=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('confidence','?'))" 2>/dev/null || echo "?")
  findings=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totalFindings',len(d.get('findings',[]))))" 2>/dev/null || echo "?")

  echo "${verdict}|${score}|${confidence}|${findings}|${duration}"
}

# ---- Scan function: Claude ----
scan_claude() {
  local url="$1"
  local safe_name="$2"
  local start_ms=$(python3 -c "import time; print(int(time.time()*1000))")

  local response
  response=$(echo "${CLAUDE_PROMPT}${url}" | timeout 120 claude --print 2>&1) || {
    echo "{\"error\":\"claude_failed\",\"raw\":\"timeout or error\"}" > "$CLAUDE_DIR/${safe_name}.json"
    echo "TIMEOUT|$url|claude timed out" >> "$ERROR_LOG"
    echo "ERROR|||0"
    return
  }

  local end_ms=$(python3 -c "import time; print(int(time.time()*1000))")
  local duration=$((end_ms - start_ms))

  # Strip markdown code fences if present
  response=$(echo "$response" | sed 's/^```json//;s/^```//')

  echo "$response" > "$CLAUDE_DIR/${safe_name}.json"

  # Extract fields
  local verdict score confidence concerns
  verdict=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('verdict','ERROR'))" 2>/dev/null || echo "ERROR")
  score=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('score','?'))" 2>/dev/null || echo "?")
  confidence=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('confidence','?'))" 2>/dev/null || echo "?")
  concerns=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('key_concerns',[])))" 2>/dev/null || echo "?")

  echo "${verdict}|${score}|${confidence}|${concerns}|${duration}"
}

# ---- Determine agreement ----
check_agreement() {
  local ac_v="$1"
  local cl_v="$2"

  # Normalize
  [[ "$ac_v" == "CONDITIONAL_PASS" ]] && ac_v="SAFE"

  if [[ "$ac_v" == "$cl_v" ]]; then
    echo "MATCH"
  elif [[ ("$ac_v" == "SAFE" || "$ac_v" == "CAUTION") && ("$cl_v" == "SAFE" || "$cl_v" == "CAUTION") ]]; then
    echo "CLOSE"
  elif [[ "$ac_v" == "ERROR" || "$cl_v" == "ERROR" ]]; then
    echo "ERROR"
  else
    echo "DISAGREE"
  fi
}

# ---- Main loop ----
DONE=0
MATCH=0
CLOSE=0
DISAGREE=0
ERRORS=0

echo "Starting scans..."
echo ""

for i in $(seq 0 $((TOTAL - 1))); do
  url="${REPOS[$i]}"
  category="${CATEGORIES[$i]}"
  safe_name=$(echo "$url" | sed 's|https://github.com/||;s|/|__|g')

  DONE=$((DONE + 1))
  printf "[%d/%d] %-50s " "$DONE" "$TOTAL" "$safe_name"

  # Run AC scan
  ac_result="ERROR|||0|0"
  if [[ "$CLAUDE_ONLY" != "true" ]]; then
    ac_result=$(scan_ac "$url" "$safe_name")
  fi

  ac_verdict=$(echo "$ac_result" | cut -d'|' -f1)
  ac_score=$(echo "$ac_result" | cut -d'|' -f2)
  ac_confidence=$(echo "$ac_result" | cut -d'|' -f3)
  ac_findings=$(echo "$ac_result" | cut -d'|' -f4)
  ac_time=$(echo "$ac_result" | cut -d'|' -f5)

  # Run Claude scan
  claude_verdict="SKIP"
  claude_score=""
  claude_confidence=""
  claude_concerns=""
  claude_time="0"

  if [[ "$AC_ONLY" != "true" ]]; then
    cl_result=$(scan_claude "$url" "$safe_name")
    claude_verdict=$(echo "$cl_result" | cut -d'|' -f1)
    claude_score=$(echo "$cl_result" | cut -d'|' -f2)
    claude_confidence=$(echo "$cl_result" | cut -d'|' -f3)
    claude_concerns=$(echo "$cl_result" | cut -d'|' -f4)
    claude_time=$(echo "$cl_result" | cut -d'|' -f5)
  fi

  # Compare
  agreement="N/A"
  if [[ "$AC_ONLY" != "true" && "$CLAUDE_ONLY" != "true" ]]; then
    agreement=$(check_agreement "$ac_verdict" "$claude_verdict")
    case "$agreement" in
      MATCH) MATCH=$((MATCH + 1)) ;;
      CLOSE) CLOSE=$((CLOSE + 1)) ;;
      DISAGREE) DISAGREE=$((DISAGREE + 1)) ;;
      ERROR) ERRORS=$((ERRORS + 1)) ;;
    esac
  fi

  # Print result line
  echo "AC:${ac_verdict}(${ac_score}) CL:${claude_verdict}(${claude_score:-?}) → ${agreement}"

  # Append to CSV
  echo "\"$url\",\"$category\",\"$ac_verdict\",\"$ac_score\",\"$ac_confidence\",\"$ac_findings\",\"$ac_time\",\"$claude_verdict\",\"${claude_score:-}\",\"${claude_confidence:-}\",\"${claude_concerns:-}\",\"$agreement\"" >> "$CSV_FILE"

  # Progress
  echo "$DONE/$TOTAL" > "$PROGRESS_FILE"

  # Rate limit delay
  sleep "$DELAY"
done

# ---- Summary ----
echo ""
echo "=========================================="
echo "BENCHMARK COMPLETE"
echo "=========================================="
echo "Total scanned: $DONE"
echo "Match:    $MATCH"
echo "Close:    $CLOSE"
echo "Disagree: $DISAGREE"
echo "Errors:   $ERRORS"
if [[ $((MATCH + CLOSE + DISAGREE)) -gt 0 ]]; then
  AGREEMENT_PCT=$(( (MATCH + CLOSE) * 100 / (MATCH + CLOSE + DISAGREE) ))
  echo "Agreement rate: ${AGREEMENT_PCT}%"
fi
echo ""
echo "Results: $RESULTS_DIR"
echo "CSV:     $CSV_FILE"
echo "Errors:  $ERROR_LOG"
echo ""
echo "Next: ./scripts/benchmark-compare.sh $RESULTS_DIR"
