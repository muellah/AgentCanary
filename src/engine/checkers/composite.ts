/**
 * Composite Checker — Combines results from multiple sub-rules
 * Detects convergence patterns (e.g., code exploit + prompt injection = campaign)
 */

import type { ACRRule, ScanTarget, CheckResult, Finding } from "../types";
import { StaticPatternChecker } from "./static";

export class CompositeChecker {
  private staticChecker: StaticPatternChecker;

  constructor(staticChecker: StaticPatternChecker) {
    this.staticChecker = staticChecker;
  }

  check(rule: ACRRule, target: ScanTarget, existingFindings: Finding[]): CheckResult {
    const subRuleIds = rule.detection.composite_rules ?? [];
    const condition = rule.detection.condition ?? "all";

    // Check how many sub-rules already fired
    const matchedSubRules = subRuleIds.filter((id) =>
      existingFindings.some((f) => f.ruleId === id)
    );

    // Also check composite's own patterns (e.g., campaign signatures)
    let ownPatternMatched = false;
    const ownMatches = [];
    if (rule.detection.patterns) {
      const staticResult = this.staticChecker.check(rule, target);
      ownPatternMatched = staticResult.matched;
      ownMatches.push(...staticResult.matches);
    }

    const totalMatched = matchedSubRules.length + (ownPatternMatched ? 1 : 0);
    const totalChecks = subRuleIds.length + (rule.detection.patterns ? 1 : 0);

    const matched = this.staticChecker.evaluateCondition(
      condition,
      totalMatched,
      totalChecks
    );

    return {
      matched,
      matches: ownMatches,
      matchedSubRules,
      score: totalMatched / Math.max(totalChecks, 1),
    };
  }
}
