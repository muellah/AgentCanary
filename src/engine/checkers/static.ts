/**
 * Static Pattern Checker — Fast regex and string matching
 */

import type { ACRRule, ScanTarget, CheckResult, MatchDetail, PatternDef } from "../types";

export class StaticPatternChecker {
  check(rule: ACRRule, target: ScanTarget): CheckResult {
    const patterns = rule.detection.patterns ?? [];
    const condition = rule.detection.condition ?? "any";
    const matches: MatchDetail[] = [];

    for (const pattern of patterns) {
      const result = this.matchPattern(pattern, target);
      if (result.matched) {
        matches.push({
          ...result,
          patternId: pattern.id,
        });
      }
    }

    const matched = this.evaluateCondition(condition, matches.length, patterns.length);
    return {
      matched,
      matches,
      score: matches.length / Math.max(patterns.length, 1),
    };
  }

  private matchPattern(pattern: PatternDef, target: ScanTarget): MatchDetail {
    if (pattern.target === "line_content") {
      return this.matchPerLine(pattern, target);
    }

    const searchText = this.getTargetText(pattern.target, target);
    if (!searchText) return { matched: false, description: pattern.description };

    if (pattern.type === "regex" && pattern._compiled) {
      pattern._compiled.lastIndex = 0;
      const m = pattern._compiled.exec(searchText);
      if (m) {
        // Find line number
        const beforeMatch = searchText.substring(0, m.index);
        const line = (beforeMatch.match(/\n/g) || []).length + 1;
        return {
          matched: true,
          description: pattern.description,
          position: m.index,
          line,
          snippet: m[0].substring(0, 200),
        };
      }
    } else if (pattern.type === "string") {
      const hay = pattern.case_sensitive === false ? searchText.toLowerCase() : searchText;
      const needle = pattern.case_sensitive === false ? pattern.value.toLowerCase() : pattern.value;
      const idx = hay.indexOf(needle);
      if (idx !== -1) {
        const beforeMatch = searchText.substring(0, idx);
        const line = (beforeMatch.match(/\n/g) || []).length + 1;
        return {
          matched: true,
          description: pattern.description,
          position: idx,
          line,
          snippet: searchText.substring(idx, idx + 100),
        };
      }
    }

    return { matched: false, description: pattern.description };
  }

  private matchPerLine(pattern: PatternDef, target: ScanTarget): MatchDetail {
    const lines = target.lines ?? target.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pattern.type === "regex" && pattern._compiled) {
        pattern._compiled.lastIndex = 0;
        if (pattern._compiled.test(line)) {
          return {
            matched: true,
            description: pattern.description,
            line: i + 1,
            snippet: line.substring(0, 200),
          };
        }
      } else if (pattern.type === "string") {
        const hay = pattern.case_sensitive === false ? line.toLowerCase() : line;
        const needle = pattern.case_sensitive === false ? pattern.value.toLowerCase() : pattern.value;
        if (hay.includes(needle)) {
          return {
            matched: true,
            description: pattern.description,
            line: i + 1,
            snippet: line.substring(0, 200),
          };
        }
      }
    }
    return { matched: false, description: pattern.description };
  }

  private getTargetText(target: string, scanTarget: ScanTarget): string {
    switch (target) {
      case "file_content":
        return scanTarget.content || "";
      case "filename":
        return scanTarget.filename || "";
      case "tool_description":
        return scanTarget.metadata?.toolDescription || "";
      case "tool_schema":
        return JSON.stringify(scanTarget.metadata?.toolSchema || {});
      case "metadata":
        return JSON.stringify(scanTarget.metadata || {});
      default:
        return scanTarget.content || "";
    }
  }

  /** Exported for composite checker reuse */
  evaluateCondition(condition: string, matchCount: number, totalPatterns: number): boolean {
    if (condition === "any") return matchCount > 0;
    if (condition === "all") return matchCount === totalPatterns;
    const countMatch = condition.match(/^count\((\d+)\)$/);
    if (countMatch) return matchCount >= parseInt(countMatch[1]);
    return matchCount > 0;
  }
}
