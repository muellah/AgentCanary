/**
 * Scan Orchestrator — Coordinates full scan workflows
 * Handles: GitHub repo scans, single file scans, pasted content
 */

import { ScanEngine, isIntentRule } from "@/engine/scanner";
import type { ScanResult, ScanTarget, Verdict, TargetType, MetadataSignals, Caveat } from "@/engine/types";
import { loadAllRules } from "./rule-registry";
import { createSemanticApiCall } from "./claude-api";
import { cloneRepo, parseGitHubUrl } from "./github-fetcher";
import { walkDirectory } from "./file-walker";
import { calculateConfidence } from "@/engine/confidence";
import { fetchQuickMetadata, fetchDeepMetadata } from "./github-metadata";
import { extractCodeMetadata } from "./metadata-extractors";

/**
 * Security tool / scanner detection keywords.
 * Repos that ARE security tools naturally contain attack patterns —
 * their findings should be downgraded from "intent" to "capability".
 */
const SECURITY_TOOL_SIGNALS = {
  /** Keywords in package.json name, description, or keywords array */
  packageKeywords: [
    "security", "scanner", "audit", "vulnerability", "pentest",
    "sast", "dast", "fuzzer", "fuzzing", "exploit", "cve",
    "semgrep", "eslint-plugin-security", "snyk", "mcp-scan",
    "detection", "threat", "malware", "antivirus",
  ],
  /** Keywords in README content (case-insensitive) */
  readmeKeywords: [
    "security scanner", "security audit", "vulnerability scanner",
    "penetration test", "security tool", "threat detection",
    "malware detection", "sast", "static analysis security",
    "security research", "exploit demo", "proof of concept",
    "security assessment", "mcp scanner", "mcp audit",
    "intentionally vulnerable", "damn vulnerable", "owasp",
  ],
  /** GitHub repo description keywords */
  descriptionKeywords: [
    "security", "scanner", "audit", "vulnerability", "pentest",
    "fuzzer", "exploit", "detection", "defense",
  ],
  /** Known security tool / trusted organizations whose repos contain attack patterns legitimately */
  trustedOrgs: [
    // Security companies
    "trailofbits", "cisco-ai-defense", "snyk", "antgroup",
    "apisec-inc", "invariantlabs-ai", "guardrails-ai",
    // AI platform companies (their skills/plugins contain instructional security content)
    "anthropics", "modelcontextprotocol", "openai", "google",
    "microsoft", "aws", "awslabs",
  ],
};

/**
 * Detect whether a repo is itself a security tool, scanner, or audit framework.
 * Returns a confidence score 0-1 (0 = not a security tool, 1 = definitely is).
 */
function detectSecurityToolRepo(
  files: Array<{ relativePath: string; content: string; isDocFile?: boolean }>,
  packageJsonContent: string | null,
  repoDescription?: string | null,
  repoOwner?: string | null,
): { isSecurityTool: boolean; confidence: number; reason: string } {
  let score = 0;
  const reasons: string[] = [];

  // Check trusted org — strong signal, alone sufficient to cross threshold
  if (repoOwner && SECURITY_TOOL_SIGNALS.trustedOrgs.includes(repoOwner.toLowerCase())) {
    score += 0.6;
    reasons.push(`trusted org: ${repoOwner}`);
  }

  // Check package.json
  if (packageJsonContent) {
    try {
      const pkg = JSON.parse(packageJsonContent);
      const searchText = [
        pkg.name || "",
        pkg.description || "",
        ...(Array.isArray(pkg.keywords) ? pkg.keywords : []),
      ].join(" ").toLowerCase();

      const matchedKeywords = SECURITY_TOOL_SIGNALS.packageKeywords.filter(kw =>
        searchText.includes(kw)
      );
      if (matchedKeywords.length >= 2) {
        score += 0.4;
        reasons.push(`package.json keywords: ${matchedKeywords.join(", ")}`);
      } else if (matchedKeywords.length === 1) {
        score += 0.2;
        reasons.push(`package.json keyword: ${matchedKeywords[0]}`);
      }
    } catch { /* ignore parse errors */ }
  }

  // Check repo description from GitHub API
  // BUT: repos that self-describe as "malicious", "vulnerable", or "exploit demo"
  // from untrusted orgs should NOT get the security tool pass
  if (repoDescription) {
    const descLower = repoDescription.toLowerCase();
    const isSelfDeclaredMalicious = /malicious|vulnerable|exploit|damn.?vulnerable|honeypot/.test(descLower);
    const isTrustedOrg = repoOwner && SECURITY_TOOL_SIGNALS.trustedOrgs.includes(repoOwner.toLowerCase());

    if (isSelfDeclaredMalicious && !isTrustedOrg) {
      // Penalize: this looks like a malicious demo from an unknown author
      score -= 0.3;
      reasons.push(`self-declared malicious from untrusted org`);
    } else {
      const matchedDesc = SECURITY_TOOL_SIGNALS.descriptionKeywords.filter(kw =>
        descLower.includes(kw)
      );
      if (matchedDesc.length >= 1) {
        score += 0.3;
        reasons.push(`repo description: ${matchedDesc.join(", ")}`);
      }
    }
  }

  // Check README
  const readmeFile = files.find(f =>
    /^readme\.md$/i.test(f.relativePath) || /^readme$/i.test(f.relativePath)
  );
  if (readmeFile) {
    const readmeLower = readmeFile.content.toLowerCase();
    const matchedReadme = SECURITY_TOOL_SIGNALS.readmeKeywords.filter(kw =>
      readmeLower.includes(kw)
    );
    if (matchedReadme.length >= 2) {
      score += 0.4;
      reasons.push(`README: ${matchedReadme.slice(0, 3).join(", ")}`);
    } else if (matchedReadme.length === 1) {
      score += 0.2;
      reasons.push(`README: ${matchedReadme[0]}`);
    }
  }

  // Check for YAML rule files (like our own rules or semgrep rules)
  const yamlRuleFiles = files.filter(f =>
    /\.(yaml|yml)$/i.test(f.relativePath) &&
    (f.content.includes("pattern:") || f.content.includes("rules:") || f.content.includes("severity:"))
  );
  if (yamlRuleFiles.length >= 3) {
    score += 0.3;
    reasons.push(`${yamlRuleFiles.length} YAML rule files detected`);
  }

  const confidence = Math.min(score, 1.0);
  return {
    isSecurityTool: confidence >= 0.5,
    confidence,
    reason: reasons.join("; ") || "no security tool signals",
  };
}

/**
 * Apply security-tool context to scan results.
 * Downgrades all findings from intent → capability (reduced penalty)
 * and recalculates per-file scores and verdicts.
 */
function applySecurityToolSuppression(results: ScanResult[]): void {
  const SEVERITY_PENALTY: Record<string, number> = {
    critical: 40, high: 25, medium: 10, low: 3, info: 0,
  };
  const CAPABILITY_FACTOR = 0.4;

  for (const result of results) {
    if (result.findings.length === 0) continue;

    // Downgrade severity: critical → medium, high → low
    for (const f of result.findings) {
      if (f.severity === "critical") f.severity = "medium";
      else if (f.severity === "high") f.severity = "low";
    }

    // Disable short-circuit (security tools aren't actually malicious)
    result.shortCircuit = false;

    // Recalculate score with all findings treated as capability-only
    const penalty = result.findings.reduce((sum, f) => {
      return sum + (SEVERITY_PENALTY[f.severity] || 5) * CAPABILITY_FACTOR;
    }, 0);
    result.score = Math.max(0, Math.min(100, Math.round(100 - penalty)));

    // Recalculate verdict
    result.verdict = result.score >= 80 ? "SAFE"
      : result.score >= 50 ? "CAUTION"
      : result.score >= 20 ? "SUSPICIOUS"
      : "DANGEROUS";
  }
}

export interface OrchestratorResult {
  success: boolean;
  results: ScanResult[];
  aggregateVerdict: Verdict;
  aggregateScore: number;
  totalFindings: number;
  filesScanned: number;
  rulesLoaded: number;
  scanDuration: number;
  /** True if any file triggered a confirmed-malicious short-circuit rule */
  shortCircuit?: boolean;
  /** Overall confidence in the aggregate verdict (0.0–1.0) */
  verdictConfidence?: number;
  /** Metadata signals collected from GitHub API and code analysis */
  metadata?: MetadataSignals;
  /** Human-readable context caveats */
  caveats?: Caveat[];
  /** True if the repo was detected as a security tool/scanner */
  isSecurityTool?: boolean;
  error?: string;
}

/**
 * Create a configured ScanEngine with rules loaded
 * @param enableSemantic - Enable LLM-powered semantic rules (expensive, use for single-file only)
 */
function createEngine(enableSemantic = false): { engine: ScanEngine; rulesLoaded: number } {
  const engine = new ScanEngine({
    apiCall: createSemanticApiCall(),
    enableSemantic,
  });
  const rules = loadAllRules();
  const { loaded } = engine.loadRules(rules);
  return { engine, rulesLoaded: loaded };
}

/**
 * Scan a GitHub repository
 */
export async function scanGitHubRepo(url: string, deepScan = false): Promise<OrchestratorResult> {
  const startMs = Date.now();
  const { engine, rulesLoaded } = createEngine();

  // Clone the repo
  const clone = await cloneRepo(url);
  if (!clone.success || !clone.localPath) {
    return {
      success: false,
      results: [],
      aggregateVerdict: "SAFE",
      aggregateScore: 100,
      totalFindings: 0,
      filesScanned: 0,
      rulesLoaded,
      scanDuration: Date.now() - startMs,
      error: clone.error,
    };
  }

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

    // Scan each file (existing logic — keep all of it unchanged)
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

    // Detect security tool repos (scanners, audit tools, etc.)
    // These naturally contain attack patterns and shouldn't be flagged as malicious
    const secToolDetection = detectSecurityToolRepo(
      files.map(f => ({ relativePath: f.relativePath, content: f.content, isDocFile: f.isDocFile })),
      packageJsonContent,
      githubMeta.repo?.description ?? null,
      parsed?.owner ?? null,
    );

    if (secToolDetection.isSecurityTool) {
      applySecurityToolSuppression(results);
    }

    // Deep scan: fetch additional signals if enabled
    let deepSignals: { contributorCount?: number; topContributorPct?: number; starsPerDay?: number } = {};
    if (deepScan && parsed && githubMeta.repo) {
      deepSignals = await fetchDeepMetadata(parsed.owner, parsed.repo, githubMeta.repo).catch(() => ({}));
    }

    // Merge all metadata signals
    const metadata: MetadataSignals = {
      author: githubMeta.author,
      repo: githubMeta.repo ? { ...githubMeta.repo, ...deepSignals } : null,
      dependencies: codeMetadata.dependencies,
      installInvasiveness: codeMetadata.installInvasiveness,
      network: codeMetadata.network,
      auth: codeMetadata.auth,
      fetchedAt: new Date().toISOString(),
      deepScan,
    };

    const result = buildAggregateResult(results, rulesLoaded, files.length, startMs, metadata);

    // Add security tool context to result
    if (secToolDetection.isSecurityTool) {
      result.isSecurityTool = true;
      result.caveats = [
        ...(result.caveats || []),
        {
          dimension: "repo_type",
          severity: "info" as const,
          text: `This repository appears to be a security tool, scanner, or from a trusted publisher (${secToolDetection.reason}). Findings have been downgraded as they likely represent detection patterns, not malicious code.`,
        },
      ];
    }

    return result;
  } finally {
    clone.cleanupFn?.();
  }
}

/**
 * Scan a single file/pasted content
 */
export async function scanContent(
  content: string,
  filename: string,
  type?: TargetType
): Promise<OrchestratorResult> {
  const startMs = Date.now();
  // Single-file scans get semantic analysis (LLM-powered) — worth the cost for one file
  const { engine, rulesLoaded } = createEngine(true);

  // Infer type from filename if not provided
  const targetType: TargetType = type ?? inferType(filename);

  const target: ScanTarget = {
    content,
    filename,
    type: targetType,
  };

  const result = await engine.scan(target);
  return buildAggregateResult([result], rulesLoaded, 1, startMs);
}

/**
 * Scan a local directory
 */
export async function scanDirectory(dirPath: string): Promise<OrchestratorResult> {
  const startMs = Date.now();
  const { engine, rulesLoaded } = createEngine();

  const files = walkDirectory(dirPath);
  const results: ScanResult[] = [];

  for (const file of files) {
    const target: ScanTarget = {
      content: file.content,
      filename: file.relativePath,
      type: file.type,
    };
    const result = await engine.scan(target);
    results.push(result);
  }

  return buildAggregateResult(results, rulesLoaded, files.length, startMs);
}

/**
 * Scan files from an upload session (single file or extracted zip).
 * Uses walkDirectory to find all scannable files in the session dir.
 */
export async function scanUploadedFile(
  sessionDir: string,
  format: string
): Promise<OrchestratorResult> {
  const startMs = Date.now();
  const enableSemantic = format !== "zip_plugin";
  const { engine, rulesLoaded } = createEngine(enableSemantic);

  const files = walkDirectory(sessionDir);
  const results: ScanResult[] = [];

  for (const file of files) {
    if (file.isDocFile && file.type !== "skill_file") continue;

    const target: ScanTarget = {
      content: file.content,
      filename: file.relativePath,
      type: file.type,
    };
    const result = await engine.scan(target);
    results.push(result);
  }

  return buildAggregateResult(results, rulesLoaded, files.length, startMs);
}

// ---- Private helpers ----

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
  } else if (worstScore >= 80 && confidence < 0.70 && metadata) {
    verdict = "CONDITIONAL_PASS";
  } else if (worstScore >= 80) {
    verdict = "SAFE"; // no metadata available (paste/file mode), trust code score
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


function inferType(filename: string): TargetType {
  const lower = filename.toLowerCase();
  if (lower.endsWith("skill.md") || lower.includes("skill")) return "skill_file";
  if (lower === "package.json") return "npm_package";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".json")) return "config_file";
  return "mcp_server";
}

/**
 * Extract package.json scripts section as a separate scan target.
 * Install hooks (preinstall, postinstall, prepare) are the #1 supply chain vector.
 */
function extractPackageJsonTargets(content: string, relativePath: string): ScanTarget[] {
  try {
    const pkg = JSON.parse(content);
    const targets: ScanTarget[] = [];

    if (pkg.scripts && typeof pkg.scripts === "object") {
      const scriptsContent = Object.entries(pkg.scripts)
        .map(([name, cmd]) => `${name}: ${cmd}`)
        .join("\n");
      targets.push({
        content: scriptsContent,
        filename: `${relativePath}[scripts]`,
        type: "npm_package",
      });
    }

    return targets;
  } catch {
    return [];
  }
}

/**
 * Extract tool descriptions from JSON files that look like MCP tool definitions.
 * Looks for objects with "name" + "description" + ("inputSchema" or "parameters").
 */
function extractToolDefinitionTargets(content: string, relativePath: string): ScanTarget[] {
  try {
    const data = JSON.parse(content);
    const targets: ScanTarget[] = [];

    function extractTools(obj: unknown): void {
      if (!obj || typeof obj !== "object") return;

      if (Array.isArray(obj)) {
        for (const item of obj) extractTools(item);
        return;
      }

      const rec = obj as Record<string, unknown>;
      // Detect tool-like objects: has name + description + schema
      if (
        typeof rec.name === "string" &&
        typeof rec.description === "string" &&
        (rec.inputSchema || rec.parameters || rec.input_schema)
      ) {
        targets.push({
          content: rec.description,
          filename: `${relativePath}[tool:${rec.name}]`,
          type: "tool_definition",
          metadata: {
            toolDescription: rec.description,
            toolSchema: (rec.inputSchema || rec.parameters || rec.input_schema) as Record<string, unknown>,
          },
        });
      }

      // Recurse into nested objects
      for (const val of Object.values(rec)) {
        if (typeof val === "object" && val !== null) extractTools(val);
      }
    }

    extractTools(data);
    return targets;
  } catch {
    return [];
  }
}
