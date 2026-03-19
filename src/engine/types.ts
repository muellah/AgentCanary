/**
 * AgentCanary Engine Types
 * Pure type definitions — no runtime dependencies
 */

// ============================================================
// RULE DEFINITIONS
// ============================================================

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type RuleStatus = "active" | "testing" | "deprecated" | "disabled";
export type CheckType = "static_pattern" | "heuristic" | "semantic" | "composite";
export type TargetType = "mcp_server" | "skill_file" | "npm_package" | "config_file" | "tool_definition" | "any";

export type Category =
  | "prompt_injection"
  | "data_exfiltration"
  | "permission_escalation"
  | "obfuscation"
  | "deceptive_behavior"
  | "dependency_risk"
  | "behavioral_manipulation"
  | "scope_creep"
  | "social_engineering"
  | "credential_harvesting"
  | "supply_chain"
  | "resource_abuse"
  | "campaign";

export interface PatternDef {
  id: string;
  description: string;
  type: "regex" | "string";
  value: string;
  target: "file_content" | "filename" | "tool_description" | "tool_schema" | "metadata" | "line_content";
  case_sensitive?: boolean;
  /** Compiled regex — populated at load time */
  _compiled?: RegExp | null;
}

export interface HeuristicCheck {
  id: string;
  description: string;
  check: string;
  threshold: number;
}

export interface SemanticCheckDef {
  model: string;
  input_field: "tool_description" | "file_content";
  system_prompt: string;
  threshold: number;
}

export interface RuleDetection {
  check_type: CheckType;
  patterns?: PatternDef[];
  condition?: string;
  heuristic_checks?: HeuristicCheck[];
  semantic_check?: SemanticCheckDef;
  pre_filter_patterns?: string[];
  composite_rules?: string[];
  /** Compiled pre-filter — populated at load time */
  _pre_filter_lower?: string[];
}

export interface ACRRule {
  id: string;
  version: string;
  title: string;
  status: RuleStatus;
  created: string;
  author: string;
  confidence: Confidence;
  severity: Severity;
  category: Category;
  subcategory?: string;
  description: string;
  tags?: string[];
  mitre?: {
    tactics: string[];
    techniques: string[];
  };
  applies_to: TargetType[];
  detection: RuleDetection;
  report?: {
    title: string;
    recommendation: string;
  };
  false_positives?: string[];
  evasion_notes?: string[];
  provenance?: {
    source: string;
    first_seen?: string;
    references?: { url: string; description: string }[];
  };
}

// ============================================================
// SCAN TARGETS AND RESULTS
// ============================================================

export interface ScanTarget {
  content: string;
  filename: string;
  type: TargetType;
  lines?: string[];
  metadata?: {
    toolDescription?: string;
    toolSchema?: Record<string, unknown>;
    toolAnnotations?: {
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
      openWorldHint?: boolean;
    };
    [key: string]: unknown;
  };
}

export interface MatchDetail {
  patternId?: string;
  checkId?: string;
  description: string;
  matched: boolean;
  line?: number;
  position?: number;
  snippet?: string;
  value?: number;
  threshold?: number;
}

export interface CheckResult {
  matched: boolean;
  matches: MatchDetail[];
  score: number;
  skipped?: boolean;
  reason?: string;
  confidence?: number;
  evidence?: string;
  model?: string;
  error?: string;
  matchedSubRules?: string[];
}

export interface Finding {
  ruleId: string;
  ruleTitle: string;
  ruleDescription: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  tags: string[];
  reportTitle: string;
  recommendation: string;
  matches: MatchDetail[];
  location: { line?: number; snippet?: string } | null;
  score: number;
  evidence: string | null;
}

export type Verdict = "SAFE" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";

export interface ScanResult {
  scanId: string;
  target: { filename: string; type: TargetType };
  startTime: string;
  endTime: string;
  rulesChecked: number;
  findings: Finding[];
  score: number;
  verdict: Verdict;
  /** True if a confirmed-malicious rule fired (instant DANGEROUS) */
  shortCircuit?: boolean;
  /** Overall confidence in the verdict (0.0–1.0) */
  verdictConfidence?: number;
  sarif: SARIFOutput;
}

// ============================================================
// SARIF OUTPUT
// ============================================================

export interface SARIFOutput {
  $schema: string;
  version: string;
  runs: {
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: unknown[];
      };
    };
    results: unknown[];
    invocations: unknown[];
  }[];
}

// ============================================================
// API TYPES (for frontend ↔ backend communication)
// ============================================================

export interface ScanRequest {
  type: "github" | "file" | "paste";
  url?: string;
  filename?: string;
  content?: string;
}

export interface ScanResponse {
  success: boolean;
  result?: ScanResult;
  /** Per-file results when scanning a repo */
  results?: ScanResult[];
  /** Aggregate verdict across all files */
  aggregateVerdict?: Verdict;
  aggregateScore?: number;
  totalFindings?: number;
  error?: string;
}
