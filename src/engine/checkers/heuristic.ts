/**
 * Heuristic Checker — Statistical and anomaly-based detection
 */

import type { ACRRule, ScanTarget, CheckResult, MatchDetail } from "../types";

export class HeuristicChecker {
  check(rule: ACRRule, target: ScanTarget): CheckResult {
    const checks = rule.detection.heuristic_checks ?? [];
    const matches: MatchDetail[] = [];

    for (const hcheck of checks) {
      const result = this.runHeuristic(hcheck, target);
      if (result.triggered) {
        matches.push({
          checkId: hcheck.id,
          description: hcheck.description,
          matched: true,
          value: result.value,
          threshold: result.threshold,
        });
      }
    }

    return {
      matched: matches.length > 0,
      matches,
      score: matches.length / Math.max(checks.length, 1),
    };
  }

  private runHeuristic(
    hcheck: { id: string; description: string; check: string; threshold: number },
    target: ScanTarget
  ): { triggered: boolean; value?: number; threshold: number } {
    const content = target.content || "";
    const lines = target.lines ?? content.split("\n");

    switch (hcheck.check) {
      case "file_size_ratio": {
        const expectedSizes: Record<string, number> = {
          "tailwind.config.js": 2000,
          "SKILL.md": 5000,
          ".js": 10000,
          ".ts": 10000,
          ".yaml": 3000,
          ".json": 5000,
        };
        const filename = target.filename || "";
        const ext = Object.keys(expectedSizes).find((e) => filename.endsWith(e));
        const expected = expectedSizes[filename] || expectedSizes[ext || ""] || 5000;
        const ratio = content.length / expected;
        return { triggered: ratio >= hcheck.threshold, value: ratio, threshold: hcheck.threshold };
      }

      case "line_length_max": {
        const maxLen = lines.reduce((max, l) => Math.max(max, l.length), 0);
        return { triggered: maxLen >= hcheck.threshold, value: maxLen, threshold: hcheck.threshold };
      }

      case "entropy_score": {
        const entropy = this.shannonEntropy(content);
        return { triggered: entropy >= hcheck.threshold, value: entropy, threshold: hcheck.threshold };
      }

      default:
        return { triggered: false, threshold: hcheck.threshold };
    }
  }

  private shannonEntropy(str: string): number {
    if (!str.length) return 0;
    const freq: Record<string, number> = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((sum, count) => {
      const p = count / len;
      return sum + p * Math.log2(p);
    }, 0);
  }
}
