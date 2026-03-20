/**
 * Scan Orchestrator — Coordinates full scan workflows
 * Handles: GitHub repo scans, single file scans, pasted content
 */

import { ScanEngine, isIntentRule } from "@/engine/scanner";
import type { ScanResult, ScanTarget, Verdict, TargetType, MetadataSignals, Caveat } from "@/engine/types";
import { loadAllRules } from "./rule-registry";
import { createSemanticApiCall } from "./claude-api";
import { cloneRepo } from "./github-fetcher";
import { walkDirectory } from "./file-walker";

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
export async function scanGitHubRepo(url: string): Promise<OrchestratorResult> {
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
    // Walk the repo files
    const files = walkDirectory(clone.localPath);
    const results: ScanResult[] = [];

    // Scan each file — skip pure documentation, demote test findings
    for (const file of files) {
      // Skip non-SKILL.md documentation files entirely — they're not attack surface
      if (file.isDocFile) continue;

      // MCP-aware extraction: parse package.json scripts as a separate scan target
      if (file.type === "npm_package") {
        const extraTargets = extractPackageJsonTargets(file.content, file.relativePath);
        for (const extra of extraTargets) {
          const extraResult = await engine.scan(extra);
          if (extraResult.findings.length > 0) results.push(extraResult);
        }
      }

      // MCP-aware extraction: parse tool definition JSON files
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

      // Demote test file findings: critical→medium, high→low
      if (file.isTestFile) {
        for (const f of result.findings) {
          if (f.severity === "critical") f.severity = "medium";
          else if (f.severity === "high") f.severity = "low";
        }
        // Recalculate score after demotion (with capability/intent weighting)
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

    return buildAggregateResult(results, rulesLoaded, files.length, startMs);
  } finally {
    // Always cleanup the cloned repo
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
  startMs: number
): OrchestratorResult {
  const allFindings = results.flatMap((r) => r.findings);

  // Short-circuit: if ANY file triggered a confirmed-malicious rule, whole repo is DANGEROUS
  const shortCircuit = results.some((r) => r.shortCircuit);

  // Aggregate score: worst file wins
  const worstScore = shortCircuit
    ? 0
    : results.length > 0
      ? Math.min(...results.map((r) => r.score))
      : 100;

  const verdict = shortCircuit ? "DANGEROUS" as Verdict : scoreToVerdict(worstScore);

  // Confidence: short-circuit = 0.95, otherwise based on finding density and severity
  const verdictConfidence = calculateVerdictConfidence(results, allFindings, shortCircuit);

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
    verdictConfidence,
  };
}

/**
 * Calculate confidence in the verdict (0.0–1.0).
 * High confidence when: short-circuit fired, many high-severity findings, or zero findings.
 * Low confidence when: borderline score, mixed severity, few findings.
 */
function calculateVerdictConfidence(
  results: ScanResult[],
  allFindings: import("@/engine/types").Finding[],
  shortCircuit: boolean
): number {
  // Short-circuit rules are high-confidence by design
  if (shortCircuit) return 0.95;

  // No findings = high confidence it's safe
  if (allFindings.length === 0) return 0.90;

  // Count by severity
  const criticalCount = allFindings.filter(f => f.severity === "critical").length;
  const highCount = allFindings.filter(f => f.severity === "high").length;
  const intentCount = allFindings.filter(f => isIntentRule(f.ruleId)).length;

  // Many critical/high findings + intent rules = high confidence malicious
  if (criticalCount >= 2 || (criticalCount >= 1 && intentCount >= 1)) return 0.90;
  if (highCount >= 3) return 0.80;

  // Borderline: some findings but not decisive
  if (allFindings.length <= 2) return 0.50;

  // Default moderate confidence
  return 0.65;
}

function scoreToVerdict(score: number): Verdict {
  if (score >= 80) return "SAFE";
  if (score >= 50) return "CAUTION";
  if (score >= 20) return "SUSPICIOUS";
  return "DANGEROUS";
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
