# AgentCanary: Security Code Review & Heuristics Improvement

## 1. General Architecture & Code Review

### Strengths
- **4-Phase Pipeline Structure:** The division of scanning into Static, Heuristic, Semantic, and Composite phases (`src/engine/scanner.ts`) is well-architected. It effectively balances fast, cheap checks (Regex, Heuristics) with slow, expensive checks (LLM via Claude API).
- **Extensible Rules Engine:** Using YAML for defining detection signatures (`src/rules/*`) is a great choice. It makes adding new rules straightforward and keeps the engine decoupled from the rule logic.
- **Pre-filtering for LLM:** The `_pre_filter_lower` in `SemanticChecker` is an excellent optimization to avoid unnecessary API calls, saving both latency and cost.
- **SARIF Compliance:** Producing SARIF v2.1.0 output natively (`src/engine/sarif-formatter.ts`) ensures standard interoperability with existing CI/CD pipelines and security dashboards.
- **Composite/Taint Tracking:** Using composite rules to detect combinations of behaviors (e.g., read + encode + network send in `ACR-C-003`) is an advanced and powerful approach to reduce false positives.

### Areas for Improvement
- **Regex Limitations:** The `StaticPatternChecker` heavily relies on regular expressions for code analysis. While fast, regex struggles with multi-line statements, string literals/comments (causing false positives), and obfuscation techniques (causing false negatives).
- **Semantic Truncation:** In `SemanticChecker`, content is truncated to 3000 characters (first 1500 and last 1500). Attackers can bypass this by padding malicious code in the middle of a very large file.
- **Hardcoded Rate Limiting:** The `SemanticChecker` uses a hardcoded 200ms sleep for rate-limiting. A proper queue or token-bucket approach would be more robust for scaling concurrent file scans.
- **Heuristics Extension Limits:** The `HeuristicChecker` (`src/engine/checkers/heuristic.ts`) currently hardcodes expected file sizes for a limited set of extensions (e.g., `.ts`, `.json`). This doesn't scale well to complex codebases.

---

## 2. Improving Security Detection Heuristics

The current heuristics (`file_size_ratio`, `line_length_max`, `entropy_score`) provide a good baseline but can be expanded to catch modern evasion techniques more reliably.

### A. Sliding Window Entropy (Local vs. Global Entropy)
**Issue:** The current `entropy_score` calculates Shannon entropy across the *entire* file. If an attacker injects a 500-byte highly obfuscated payload into a 50KB legitimate file, the overall file entropy will remain normal.
**Improvement:**
- Calculate entropy over a **sliding window** (e.g., 256 or 512 bytes) or on a **per-line basis**.
- Flag files that have localized spikes in entropy, even if the overall file entropy is low.
- Track string literal entropy separately from code structure entropy.

### B. AST-Based Structural Heuristics
**Issue:** Regex and basic text analysis cannot understand code structure, making them susceptible to trivial obfuscation (e.g., renaming variables, splitting strings).
**Improvement:** Integrate a lightweight AST parser (like `acorn` for JS/TS) to extract structural heuristics:
- **AST Node Depth:** Obfuscated code often results in unusually deep AST structures (e.g., heavily nested arrays or function calls).
- **Cyclomatic Complexity:** Calculate the complexity of functions. Auto-generated obfuscated malware often has massive single functions with extremely high complexity.
- **Operator to Operand Ratio:** Obfuscators often use excessive operators (e.g., `!![]`, `+""`, `~-`) to represent simple values. Analyzing this ratio can reliably detect packed code.

### C. Whitespace and Character Distribution Analysis
**Improvement:**
- **Whitespace Density:** Minified or obfuscated code has an abnormally low ratio of whitespace to characters. While normal minified code also triggers this, combining it with high entropy or suspicious API usage raises confidence.
- **Symbol Distribution:** Count the frequency of non-alphanumeric characters. Techniques like "JSFuck" or deeply encoded arrays use an unusual distribution of brackets `[]`, parentheses `()`, and backticks `` ` ``.

### D. Data Taint / Import Resolution Heuristics
**Issue:** The composite taint chain (`ACR-C-003`) relies on finding read, encode, and send keywords anywhere in the same file via regex. This can trigger false positives if a file naturally reads configs and makes API calls separately.
**Improvement:**
- Build a heuristic that tracks the **proximity** of sensitive API calls. If `process.env` or `fs.readFileSync` is called within N lines (or within the same AST scope) as `fetch` or `axios.post`, the risk score should multiply.
- Check for **Dynamic Imports & Obfuscated Executions:** Detect patterns like `require(variable)` or `eval(String.fromCharCode(...))`.

### E. Expanded Heuristic Check Types
To support the above, `HeuristicChecker` (`src/engine/checkers/heuristic.ts`) could be expanded with new checks:
1. `max_string_literal_length`: Find exceptionally long base64 or hex encoded strings.
2. `suspicious_variable_names`: Analyze the ratio of variables with 1-2 character names, or variables named with hex patterns (e.g., `_0x1a2b`), which are common in obfuscators.
3. `comment_to_code_ratio`: Extremely low comment density in large files might indicate machine-generated or obfuscated payloads (though typical of minified code, can be used as a contributing signal).

---

## 3. Recommendations & Next Steps

1. **Implement Localized Entropy:** Modify `shannonEntropy` to support chunks or line-by-line analysis, and update `ACR-H-002` to use `max_chunk_entropy`.
2. **Add a Lightweight AST parser:** Use a library like `acorn` or `tree-sitter` for the `StaticPatternChecker` and `HeuristicChecker`. This enables extracting string literals to check their specific entropy and detecting dynamic imports accurately.
3. **Refine Truncation:** For `SemanticChecker`, instead of blindly truncating the middle, use a heuristic to extract the most "suspicious" chunks (e.g., the chunks with the highest entropy or containing sensitive regex matches) and send *those* to the LLM.
4. **Proceed with Phase 2 Metadata Context:** The planned metadata framework (GitHub API context, contributor patterns, age, etc.) documented in the specs is an excellent approach to solving the false-positive problem with legitimate capabilities in MCP tools.
