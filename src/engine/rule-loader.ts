/**
 * Rule Loader — Parses ACR YAML rules into executable format
 * Pure TypeScript, no web dependencies
 */

import type { ACRRule, CheckType, Category } from "./types";

export class RuleLoader {
  private rules = new Map<string, ACRRule>();
  private rulesByCategory = new Map<Category, string[]>();
  private rulesByType = new Map<CheckType, string[]>();

  /**
   * Load a single rule from parsed YAML object.
   * Compiles regex patterns for performance.
   */
  loadRule(ruleObj: ACRRule): boolean {
    const required: (keyof ACRRule)[] = [
      "id", "version", "title", "status", "severity", "category", "detection",
    ];
    for (const field of required) {
      if (!ruleObj[field]) {
        console.warn(`Rule ${ruleObj.id || "unknown"}: missing required field '${field}'`);
        return false;
      }
    }

    // Only load active/testing rules
    if (!["active", "testing"].includes(ruleObj.status)) {
      return false;
    }

    // Compile regex patterns
    if (ruleObj.detection.patterns) {
      for (const pattern of ruleObj.detection.patterns) {
        if (pattern.type === "regex") {
          try {
            const flags = pattern.case_sensitive === false ? "gi" : "g";
            pattern._compiled = new RegExp(pattern.value, flags);
          } catch (e) {
            console.warn(
              `Rule ${ruleObj.id}: invalid regex '${pattern.value}': ${(e as Error).message}`
            );
            pattern._compiled = null;
          }
        }
      }
    }

    // Compile pre-filter patterns
    if (ruleObj.detection.pre_filter_patterns) {
      ruleObj.detection._pre_filter_lower = ruleObj.detection.pre_filter_patterns.map(
        (p) => p.toLowerCase()
      );
    }

    this.rules.set(ruleObj.id, ruleObj);

    // Index by category
    const catList = this.rulesByCategory.get(ruleObj.category) ?? [];
    catList.push(ruleObj.id);
    this.rulesByCategory.set(ruleObj.category, catList);

    // Index by check type
    const checkType = ruleObj.detection.check_type;
    const typeList = this.rulesByType.get(checkType) ?? [];
    typeList.push(ruleObj.id);
    this.rulesByType.set(checkType, typeList);

    return true;
  }

  /**
   * Load multiple rules from an array
   */
  loadRules(ruleArray: ACRRule[]): { loaded: number; total: number; errors: string[] } {
    let loaded = 0;
    const errors: string[] = [];
    for (const rule of ruleArray) {
      try {
        if (this.loadRule(rule)) loaded++;
      } catch (e) {
        errors.push(`${rule.id || "unknown"}: ${(e as Error).message}`);
      }
    }
    return { loaded, total: ruleArray.length, errors };
  }

  getRule(id: string): ACRRule | undefined {
    return this.rules.get(id);
  }

  getAllRules(): ACRRule[] {
    return Array.from(this.rules.values());
  }

  getRulesByCategory(cat: Category): ACRRule[] {
    return (this.rulesByCategory.get(cat) ?? []).map(
      (id) => this.rules.get(id)!
    );
  }

  getRulesByType(type: CheckType): ACRRule[] {
    return (this.rulesByType.get(type) ?? []).map(
      (id) => this.rules.get(id)!
    );
  }

  getStats() {
    return {
      total: this.rules.size,
      byCategory: Object.fromEntries(
        Array.from(this.rulesByCategory.entries()).map(([k, v]) => [k, v.length])
      ),
      byType: Object.fromEntries(
        Array.from(this.rulesByType.entries()).map(([k, v]) => [k, v.length])
      ),
      bySeverity: this.countBy("severity"),
    };
  }

  private countBy(field: keyof ACRRule): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const rule of this.rules.values()) {
      const val = rule[field] as string;
      counts[val] = (counts[val] || 0) + 1;
    }
    return counts;
  }
}
