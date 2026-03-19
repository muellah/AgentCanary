/**
 * Semantic Checker — LLM-powered analysis via Claude API
 * Handles pre-filtering, API calls, response parsing
 */

import type { ACRRule, ScanTarget, CheckResult } from "../types";

export type SemanticApiCall = (
  model: string,
  systemPrompt: string,
  userContent: string
) => Promise<string>;

export class SemanticChecker {
  private apiCall: SemanticApiCall | null;

  constructor(options: { apiCall?: SemanticApiCall } = {}) {
    this.apiCall = options.apiCall ?? null;
  }

  async check(rule: ACRRule, target: ScanTarget): Promise<CheckResult> {
    const detection = rule.detection;

    // Fast pre-filter: skip expensive AI call if no trigger patterns found
    if (detection._pre_filter_lower && detection._pre_filter_lower.length > 0) {
      const contentLower = (target.content || "").toLowerCase();
      const toolDescLower = (target.metadata?.toolDescription || "").toLowerCase();
      const searchText = contentLower + " " + toolDescLower;
      const hasPreFilter = detection._pre_filter_lower.some((p) => searchText.includes(p));
      if (!hasPreFilter) {
        return { matched: false, matches: [], score: 0, skipped: true, reason: "pre_filter_no_match" };
      }
    }

    if (!this.apiCall) {
      return { matched: false, matches: [], score: 0, skipped: true, reason: "no_api_configured" };
    }

    const semCheck = detection.semantic_check;
    if (!semCheck) return { matched: false, matches: [], score: 0 };

    try {
      // Rate limit: max 1 call per 200ms to avoid blowing through credits
      await new Promise((resolve) => setTimeout(resolve, 200));

      const inputText = this.getInput(semCheck.input_field, target);

      // Skip very short content — not enough signal for semantic analysis
      if (inputText.length < 50) {
        return { matched: false, matches: [], score: 0, skipped: true, reason: "content_too_short" };
      }

      // Truncate to prevent excessive token usage (max ~3000 chars)
      const truncated = inputText.length > 3000
        ? inputText.substring(0, 1500) + "\n...[truncated]...\n" + inputText.substring(inputText.length - 1500)
        : inputText;

      // 10-second timeout per API call
      const timeoutPromise = new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error("Semantic check timed out after 10s")), 10_000)
      );
      const response = await Promise.race([
        this.apiCall(semCheck.model, semCheck.system_prompt, truncated),
        timeoutPromise,
      ]);

      // Parse JSON response from AI
      const clean = response.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim();
      const result = JSON.parse(clean);

      const confidence = result.confidence || 0;
      const matched = confidence >= (semCheck.threshold || 0.7);

      return {
        matched,
        matches: matched
          ? [
              {
                matched: true,
                description: `Semantic analysis: ${result.evidence || result.technique || "suspicious content detected"}`,
                snippet: (result.evidence || "").substring(0, 200),
              },
            ]
          : [],
        score: confidence,
        confidence,
        evidence: result.evidence || result.findings || "",
        model: semCheck.model,
      };
    } catch (err) {
      return {
        matched: false,
        matches: [],
        score: 0,
        error: (err as Error).message,
      };
    }
  }

  private getInput(inputField: string, target: ScanTarget): string {
    switch (inputField) {
      case "tool_description":
        return target.metadata?.toolDescription || target.content;
      case "file_content":
        return target.content;
      default:
        return target.content;
    }
  }
}
