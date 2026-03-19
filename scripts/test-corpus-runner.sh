#!/bin/bash
# AgentCanary Test Corpus Runner
# Scans legitimate + malicious repos and reports FP/FN rates
# Usage: ./scripts/test-corpus-runner.sh [--legit-only] [--malicious-only]

set -e
export PATH="/usr/local/bin:/usr/bin:$PATH"

BASE_URL="http://localhost:3000"
RESULTS_DIR="test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/run_$TIMESTAMP.json"

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "AgentCanary Test Corpus Runner"
echo "=========================================="
echo ""

# Check server is running
if ! curl -s "$BASE_URL" > /dev/null 2>&1; then
  echo "ERROR: Server not running at $BASE_URL"
  echo "Start it with: npm run dev"
  exit 1
fi

# ---- LEGITIMATE REPOS ----
LEGIT_REPOS=(
  "modelcontextprotocol/typescript-sdk"
  "modelcontextprotocol/python-sdk"
  "modelcontextprotocol/inspector"
  "microsoft/playwright-mcp"
  "github/github-mcp-server"
  "ChromeDevTools/chrome-devtools-mcp"
  "PrefectHQ/fastmcp"
  "GLips/Figma-Context-MCP"
  "tadata-org/fastapi_mcp"
  "awslabs/mcp"
  "idosal/git-mcp"
  "mcp-use/mcp-use"
  "lastmile-ai/mcp-agent"
  "AgentDeskAI/browser-tools-mcp"
  "grab/cursor-talk-to-figma-mcp"
  "microsoft/mcp-for-beginners"
  "BeehiveInnovations/pal-mcp-server"
  "hangwin/mcp-chrome"
  "LaurieWired/GhidraMCP"
  "CoplayDev/unity-mcp"
)

# ---- MALICIOUS REPOS ----
MALICIOUS_REPOS=(
  "appsecco/vulnerable-mcp-servers-lab"
  "YassWorks/Malicious-MCP-Server"
  "harishsg993010/damn-vulnerable-MCP-server"
  "smart-mcp-proxy/malicious-demo-mcp-server"
  "Cyberency/CVE-2025-6514"
  "aztr0nutzs/NET_NiNjA.v1.2"
)

# ---- LOCAL MALICIOUS SAMPLES ----
MALICIOUS_FILES=(
  "research/malicious-samples/raw/clawhub-SKILL.md"
  "research/malicious-samples/raw/coding-agent-1gx-SKILL.md"
  "research/malicious-samples/raw/google-qx4-SKILL.md"
  "research/malicious-samples/raw/whatsapp-mgv-SKILL.md"
)

echo "Legitimate repos: ${#LEGIT_REPOS[@]}"
echo "Malicious repos: ${#MALICIOUS_REPOS[@]}"
echo "Malicious files: ${#MALICIOUS_FILES[@]}"
echo ""

# Initialize results
python3 -c "
import json
results = {
    'timestamp': '$TIMESTAMP',
    'legitimate': [],
    'malicious_repos': [],
    'malicious_files': [],
    'summary': {}
}
with open('$RESULTS_FILE', 'w') as f:
    json.dump(results, f)
"

# ---- SCAN LEGITIMATE REPOS ----
if [[ "$1" != "--malicious-only" ]]; then
  echo "=== SCANNING LEGITIMATE REPOS ==="
  echo ""

  LEGIT_PASS=0
  LEGIT_FAIL=0
  LEGIT_ERROR=0

  for repo in "${LEGIT_REPOS[@]}"; do
    echo -n "  Scanning $repo... "
    RESPONSE=$(curl -s -m 120 -X POST "$BASE_URL/api/scan/github" \
      -H "Content-Type: application/json" \
      -d "{\"url\":\"https://github.com/$repo\"}" 2>&1)

    VERDICT=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateVerdict','ERROR'))" 2>/dev/null || echo "ERROR")
    SCORE=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateScore','?'))" 2>/dev/null || echo "?")
    FINDINGS=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totalFindings','?'))" 2>/dev/null || echo "?")

    # For legit repos: SAFE or CAUTION is pass, SUSPICIOUS or DANGEROUS is fail
    if [[ "$VERDICT" == "SAFE" || "$VERDICT" == "CAUTION" ]]; then
      echo "PASS ($VERDICT, score=$SCORE, findings=$FINDINGS)"
      ((LEGIT_PASS++))
    elif [[ "$VERDICT" == "ERROR" ]]; then
      echo "ERROR"
      ((LEGIT_ERROR++))
    else
      echo "FAIL ($VERDICT, score=$SCORE, findings=$FINDINGS) <-- FALSE POSITIVE"
      ((LEGIT_FAIL++))
    fi

    # Save result
    python3 -c "
import json
with open('$RESULTS_FILE') as f:
    data = json.load(f)
try:
    result = json.loads('''$RESPONSE''')
    data['legitimate'].append({
        'repo': '$repo',
        'verdict': result.get('aggregateVerdict'),
        'score': result.get('aggregateScore'),
        'findings': result.get('totalFindings'),
        'filesScanned': result.get('filesScanned'),
        'pass': result.get('aggregateVerdict') in ['SAFE', 'CAUTION']
    })
except:
    data['legitimate'].append({'repo': '$repo', 'verdict': 'ERROR', 'pass': False})
with open('$RESULTS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null

    sleep 1  # Be nice to GitHub
  done

  echo ""
  echo "Legitimate repos: $LEGIT_PASS pass, $LEGIT_FAIL FAIL (FP), $LEGIT_ERROR error"
  echo "False positive rate: $LEGIT_FAIL / $((LEGIT_PASS + LEGIT_FAIL))"
  echo ""
fi

# ---- SCAN MALICIOUS REPOS ----
if [[ "$1" != "--legit-only" ]]; then
  echo "=== SCANNING MALICIOUS REPOS ==="
  echo ""

  MAL_PASS=0
  MAL_FAIL=0
  MAL_ERROR=0

  for repo in "${MALICIOUS_REPOS[@]}"; do
    echo -n "  Scanning $repo... "
    RESPONSE=$(curl -s -m 120 -X POST "$BASE_URL/api/scan/github" \
      -H "Content-Type: application/json" \
      -d "{\"url\":\"https://github.com/$repo\"}" 2>&1)

    VERDICT=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateVerdict','ERROR'))" 2>/dev/null || echo "ERROR")
    SCORE=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateScore','?'))" 2>/dev/null || echo "?")
    FINDINGS=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totalFindings','?'))" 2>/dev/null || echo "?")

    # For malicious repos: SUSPICIOUS or DANGEROUS is pass, SAFE is fail
    if [[ "$VERDICT" == "SUSPICIOUS" || "$VERDICT" == "DANGEROUS" ]]; then
      echo "PASS ($VERDICT, score=$SCORE, findings=$FINDINGS)"
      ((MAL_PASS++))
    elif [[ "$VERDICT" == "ERROR" ]]; then
      echo "ERROR"
      ((MAL_ERROR++))
    else
      echo "FAIL ($VERDICT, score=$SCORE, findings=$FINDINGS) <-- FALSE NEGATIVE"
      ((MAL_FAIL++))
    fi

    python3 -c "
import json
with open('$RESULTS_FILE') as f:
    data = json.load(f)
try:
    result = json.loads('''$RESPONSE''')
    data['malicious_repos'].append({
        'repo': '$repo',
        'verdict': result.get('aggregateVerdict'),
        'score': result.get('aggregateScore'),
        'findings': result.get('totalFindings'),
        'pass': result.get('aggregateVerdict') in ['SUSPICIOUS', 'DANGEROUS']
    })
except:
    data['malicious_repos'].append({'repo': '$repo', 'verdict': 'ERROR', 'pass': False})
with open('$RESULTS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null

    sleep 1
  done

  echo ""
  echo "Malicious repos: $MAL_PASS detected, $MAL_FAIL MISSED (FN), $MAL_ERROR error"
  echo ""

  # ---- SCAN LOCAL MALICIOUS FILES ----
  echo "=== SCANNING LOCAL MALICIOUS FILES ==="
  echo ""

  MAL_FILE_PASS=0
  MAL_FILE_FAIL=0

  for filepath in "${MALICIOUS_FILES[@]}"; do
    if [[ ! -f "$filepath" ]]; then
      echo "  SKIP: $filepath (not found)"
      continue
    fi

    echo -n "  Scanning $filepath... "
    CONTENT=$(python3 -c "
import json
with open('$filepath') as f:
    c = f.read()
lines = [l for l in c.split('\n') if not l.startswith('permalink:')]
print(json.dumps({'content': '\n'.join(lines), 'filename': '$(basename $filepath)'}))
" 2>/dev/null)

    RESPONSE=$(curl -s -m 30 -X POST "$BASE_URL/api/scan/file" \
      -H "Content-Type: application/json" \
      -d "$CONTENT" 2>&1)

    VERDICT=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateVerdict','ERROR'))" 2>/dev/null || echo "ERROR")
    SCORE=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aggregateScore','?'))" 2>/dev/null || echo "?")
    FINDINGS=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totalFindings','?'))" 2>/dev/null || echo "?")

    if [[ "$VERDICT" == "SUSPICIOUS" || "$VERDICT" == "DANGEROUS" ]]; then
      echo "PASS ($VERDICT, score=$SCORE, findings=$FINDINGS)"
      ((MAL_FILE_PASS++))
    else
      echo "FAIL ($VERDICT, score=$SCORE, findings=$FINDINGS) <-- FALSE NEGATIVE"
      ((MAL_FILE_FAIL++))
    fi
  done

  echo ""
  echo "Malicious files: $MAL_FILE_PASS detected, $MAL_FILE_FAIL MISSED (FN)"
fi

echo ""
echo "=========================================="
echo "FINAL SUMMARY"
echo "=========================================="
