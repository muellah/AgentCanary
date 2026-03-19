/**
 * Rule Registry — Loads all YAML rules from disk, caches them
 * Singleton pattern: rules are loaded once at startup
 */

import { readFileSync, readdirSync, existsSync } from "fs";
import { join, extname } from "path";
import yaml from "js-yaml";
import type { ACRRule } from "@/engine/types";

let cachedRules: ACRRule[] | null = null;

/**
 * Load all YAML rules from the rules/ directory tree
 */
export function loadAllRules(rulesDir?: string): ACRRule[] {
  if (cachedRules) return cachedRules;

  const baseDir = rulesDir ?? join(process.cwd(), "src", "rules");
  const rules: ACRRule[] = [];

  function walkRules(dir: string) {
    if (!existsSync(dir)) return;
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walkRules(fullPath);
      } else if (extname(entry.name) === ".yaml" || extname(entry.name) === ".yml") {
        try {
          const content = readFileSync(fullPath, "utf-8");
          const parsed = yaml.load(content) as ACRRule;
          if (parsed && parsed.id) {
            rules.push(parsed);
          }
        } catch (err) {
          console.warn(`Failed to load rule ${fullPath}: ${(err as Error).message}`);
        }
      }
    }
  }

  walkRules(baseDir);
  cachedRules = rules;
  return rules;
}

/**
 * Force reload rules (useful for development)
 */
export function reloadRules(rulesDir?: string): ACRRule[] {
  cachedRules = null;
  return loadAllRules(rulesDir);
}
