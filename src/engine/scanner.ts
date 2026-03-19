/**
 * Scan Engine — Orchestrates the 4-phase detection pipeline
 *
 * Phase 1: Static pattern checks (fast, regex-based)
 * Phase 2: Heuristic checks (fast, statistical)
 * Phase 3: Semantic checks (slow, LLM-powered)
 * Phase 4: Composite checks (combine sub-rule results)
 */

import type {
  ACRRule,
  ScanTarget,
  ScanResult,
  Finding,
  Verdict,
  CheckResult,
} from "./types";
import { RuleLoader } from "./rule-loader";
import {
  StaticPatternChecker,
  HeuristicChecker,
  SemanticChecker,
  CompositeChecker,
} from "./checkers";
import type { SemanticApiCall } from "./checkers";
import { SARIFFormatter } from "./sarif-formatter";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Rules that, when fired, indicate confirmed malicious intent (not just capability).
 * Any match → instant DANGEROUS verdict, score 0, regardless of other files.
 */
const SHORT_CIRCUIT_RULES = new Set([
  "ACR-S-019", // Reverse shell patterns
  "ACR-S-020", // Webhook exfiltration (Discord/Slack/Telegram)
  "ACR-S-027", // Data interception and dual-channel exfiltration
  "ACR-C-003", // Taint chain: read + encode + send
  "ACR-C-001", // Supply chain: install hook + code execution
  // NOTE: ACR-S-021 (credential file access) deliberately NOT here —
  // reading .env files is common in legitimate MCP servers.
]);

const SEVERITY_PENALTY: Record<string, number> = {
  critical: 40,
  high: 25,
  medium: 10,
  low: 3,
  info: 0,
};

/**
 * Rules that indicate INTENT (confirmed malicious behavior), not just capability.
 * Intent rules get full penalty. Capability rules (not in this set) get 40% penalty.
 * This prevents legitimate tools with powerful capabilities from being over-penalized.
 */
const INTENT_RULES = new Set([
  // Exfiltration (ACR-S-021 excluded — reading .env is common in legit code)
  "ACR-S-004", "ACR-S-005", "ACR-S-006", "ACR-S-020",
  // Code execution / reverse shell
  "ACR-S-019",
  // Obfuscation (why obfuscate if not malicious?)
  "ACR-S-002", "ACR-S-017",
  // Supply chain attacks
  "ACR-S-010", "ACR-S-018", "ACR-S-022",
  // Social engineering / deception
  "ACR-S-015", "ACR-S-023",
  // Prompt injection / social engineering injection
  "ACR-S-001", "ACR-S-028",
  // Data interception
  "ACR-S-027",
  // Financial bait
  "ACR-S-016",
  // All semantic rules (LLM confirmed intent)
  "ACR-M-001", "ACR-M-002", "ACR-M-003", "ACR-M-004", "ACR-M-005", "ACR-M-006", "ACR-M-007",
  // All composite rules (multi-signal = intent)
  "ACR-C-001", "ACR-C-002", "ACR-C-003",
  // CVE rules
  "ACR-V-001", "ACR-V-002", "ACR-V-003",
]);

/** Capability-only penalty multiplier (40% of full penalty) */
const CAPABILITY_PENALTY_FACTOR = 0.4;

/** Check if a rule ID indicates intent (not just capability) */
export function isIntentRule(ruleId: string): boolean {
  return INTENT_RULES.has(ruleId);
}

export class ScanEngine {
  private loader: RuleLoader;
  private staticChecker: StaticPatternChecker;
  private heuristicChecker: HeuristicChecker;
  private semanticChecker: SemanticChecker;
  private compositeChecker: CompositeChecker;
  private sarifFormatter: SARIFFormatter;
  /** Enable semantic (LLM) checks. Off by default for repo scans, on for single-file. */
  public enableSemantic = false;

  constructor(options: { apiCall?: SemanticApiCall; enableSemantic?: boolean } = {}) {
    this.loader = new RuleLoader();
    this.staticChecker = new StaticPatternChecker();
    this.heuristicChecker = new HeuristicChecker();
    this.semanticChecker = new SemanticChecker({ apiCall: options.apiCall });
    this.compositeChecker = new CompositeChecker(this.staticChecker);
    this.sarifFormatter = new SARIFFormatter();
    this.enableSemantic = options.enableSemantic ?? false;
  }

  loadRules(ruleArray: ACRRule[]) {
    return this.loader.loadRules(ruleArray);
  }

  /**
   * Run a full 4-phase scan against a single target
   */
  async scan(target: ScanTarget): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const findings: Finding[] = [];
    const lines = (target.content || "").split("\n");
    const scanTarget: ScanTarget = { ...target, lines };

    // Get applicable rules for this target type
    const allRules = this.loader.getAllRules();
    const applicableRules = allRules.filter(
      (rule) =>
        rule.applies_to.includes(target.type) ||
        rule.applies_to.includes("any" as never)
    );

    // Phase 1: Static pattern checks (fast)
    for (const rule of this.getRulesOfType(applicableRules, "static_pattern")) {
      const result = this.staticChecker.check(rule, scanTarget);
      if (result.matched) {
        findings.push(this.buildFinding(rule, result));
      }
    }

    // Phase 2: Heuristic checks (fast)
    for (const rule of this.getRulesOfType(applicableRules, "heuristic")) {
      const result = this.heuristicChecker.check(rule, scanTarget);
      if (result.matched) {
        findings.push(this.buildFinding(rule, result));
      }
    }

    // Phase 3: Semantic checks (slow, LLM-powered)
    // COST + ACCURACY CONTROL: Only run semantic on single-file scans (paste/upload),
    // NOT on bulk repo scans. Repo scans use static rules only — the LLM produces
    // too many false positives on legitimate MCP server code.
    // The enableSemantic flag is set by the caller (scanContent vs scanGitHubRepo).
    if (this.enableSemantic) {
      for (const rule of this.getRulesOfType(applicableRules, "semantic")) {
        const result = await this.semanticChecker.check(rule, scanTarget);
        if (result.matched) {
          findings.push(this.buildFinding(rule, result));
        }
      }
    }

    // Phase 4: Composite checks (combine sub-rule results)
    for (const rule of this.getRulesOfType(applicableRules, "composite")) {
      const result = this.compositeChecker.check(rule, scanTarget, findings);
      if (result.matched) {
        findings.push(this.buildFinding(rule, result));
      }
    }

    // Sort findings by severity
    findings.sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
    );

    const endTime = new Date().toISOString();

    // Short-circuit: if any confirmed-malicious rule fired, instant DANGEROUS
    const shortCircuitFired = findings.some(f => SHORT_CIRCUIT_RULES.has(f.ruleId));
    const score = shortCircuitFired ? 0 : this.calculateScore(findings);
    const verdict = shortCircuitFired ? "DANGEROUS" as Verdict : this.scoreToVerdict(score);

    return {
      scanId: `scan-${Date.now()}`,
      target: { filename: target.filename, type: target.type },
      startTime,
      endTime,
      rulesChecked: applicableRules.length,
      findings,
      score,
      verdict,
      shortCircuit: shortCircuitFired,
      sarif: this.sarifFormatter.format(findings, {
        targetUri: target.filename,
        startTime,
        endTime,
      }),
    };
  }

  getStats() {
    return this.loader.getStats();
  }

  // ---- Private helpers ----

  private getRulesOfType(rules: ACRRule[], type: string): ACRRule[] {
    return rules.filter((r) => r.detection.check_type === type);
  }

  private buildFinding(rule: ACRRule, result: CheckResult): Finding {
    return {
      ruleId: rule.id,
      ruleTitle: rule.title,
      ruleDescription: rule.description,
      severity: rule.severity,
      confidence: rule.confidence,
      category: rule.category,
      tags: rule.tags || [],
      reportTitle: rule.report?.title || rule.title,
      recommendation: rule.report?.recommendation || "",
      matches: result.matches || [],
      location:
        result.matches?.[0]?.line || result.matches?.[0]?.snippet
          ? {
              line: result.matches[0].line,
              snippet: result.matches[0].snippet,
            }
          : null,
      score: result.score || 0,
      evidence: result.evidence || null,
    };
  }

  private calculateScore(findings: Finding[]): number {
    if (findings.length === 0) return 100;
    let penalty = 0;
    for (const f of findings) {
      const basePenalty = SEVERITY_PENALTY[f.severity] || 5;
      // Intent rules get full penalty; capability-only rules get reduced penalty
      const factor = INTENT_RULES.has(f.ruleId) ? 1.0 : CAPABILITY_PENALTY_FACTOR;
      penalty += basePenalty * factor;
    }
    return Math.max(0, Math.min(100, Math.round(100 - penalty)));
  }

  private scoreToVerdict(score: number): Verdict {
    if (score >= 80) return "SAFE";
    if (score >= 50) return "CAUTION";
    if (score >= 20) return "SUSPICIOUS";
    return "DANGEROUS";
  }
}
