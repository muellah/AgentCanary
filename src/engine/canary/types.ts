/**
 * Canary Token Types
 * Type definitions for the canary token detection system
 */

// ============================================================
// CANARY TOKEN TYPES
// ============================================================

export type CanaryType =
  | "tool_pin"
  | "prompt_injection"
  | "credential"
  | "filesystem"
  | "network";

export type CanaryMode = "leak" | "hijack";

export type CanaryStatus = "active" | "triggered" | "expired" | "inactive";

export interface CanaryToken {
  /** Unique identifier for this canary */
  id: string;
  /** Type of canary token */
  type: CanaryType;
  /** The raw token value (e.g. hex string) */
  value: string;
  /** Formatted token ready for embedding (e.g. HTML comment) */
  formatted: string;
  /** When the canary was created */
  createdAt: string;
  /** Optional expiry time */
  expiresAt?: string;
  /** Current status */
  status: CanaryStatus;
  /** Additional metadata depending on canary type */
  metadata?: Record<string, unknown>;
}

export interface CanaryActivation {
  /** The canary that was triggered */
  canaryId: string;
  /** Type of canary that fired */
  type: CanaryType;
  /** When the activation was detected */
  detectedAt: string;
  /** What triggered it */
  trigger: CanaryTrigger;
  /** Severity of the activation */
  severity: "critical" | "high" | "medium" | "low";
  /** Human-readable description */
  description: string;
}

export type CanaryTrigger =
  | ToolPinTrigger
  | PromptLeakTrigger
  | PromptHijackTrigger;

export interface ToolPinTrigger {
  kind: "tool_pin_mismatch";
  /** Tool identifier that changed */
  toolId: string;
  /** Original hash at pin time */
  originalHash: string;
  /** New hash at re-scan time */
  currentHash: string;
}

export interface PromptLeakTrigger {
  kind: "prompt_leak";
  /** The canary token that was found in output */
  token: string;
  /** Where the token appeared */
  location: string;
}

export interface PromptHijackTrigger {
  kind: "prompt_hijack";
  /** The canary token that should have appeared */
  token: string;
  /** The output that was checked */
  checkedOutput: string;
}

// ============================================================
// TOOL PIN TYPES
// ============================================================

export interface ToolPin {
  /** Tool identifier (e.g. server name + tool name) */
  toolId: string;
  /** SHA-256 hash of the canonical tool definition JSON */
  hash: string;
  /** When this pin was created */
  pinnedAt: string;
  /** The tool definition that was hashed (for diff display) */
  definition: Record<string, unknown>;
}

export interface PinFile {
  /** Schema version for the pin file */
  version: string;
  /** When the pin file was last updated */
  updatedAt: string;
  /** Map of toolId -> ToolPin */
  pins: Record<string, ToolPin>;
}

// ============================================================
// PROMPT CANARY TYPES
// ============================================================

export interface PromptCanaryOptions {
  /** Mode: leak detection or hijack detection */
  mode: CanaryMode;
  /** Custom token length in bytes (default 8 = 16 hex chars) */
  tokenBytes?: number;
  /** Custom format function for the token */
  formatFn?: (token: string) => string;
}

export interface PromptCanaryResult {
  /** Whether the canary was triggered */
  triggered: boolean;
  /** The mode that was tested */
  mode: CanaryMode;
  /** The canary token used */
  token: string;
  /** Details about the detection */
  detail: string;
}
