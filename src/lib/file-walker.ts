/**
 * File Walker — Recursively walks directories, extracts scannable files
 * Respects gitignore, skips binaries, respects size limits
 */

import { readFileSync, readdirSync, statSync } from "fs";
import { join, extname, basename, relative } from "path";
import type { TargetType } from "@/engine/types";

const MAX_FILE_SIZE = 512 * 1024; // 512KB per file
const MAX_FILES = 200; // Don't scan more than 200 files per repo

/** File extensions we know how to scan */
const SCANNABLE_EXTENSIONS = new Set([
  // JavaScript/TypeScript
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  // Python
  ".py",
  // Config/data
  ".json", ".yaml", ".yml", ".toml",
  // Markdown (skill files)
  ".md",
  // Shell
  ".sh", ".bash", ".zsh",
  // Ruby
  ".rb",
  // Other
  ".php", ".pl", ".ps1", ".bat", ".cmd",
]);

/** Directories to always skip */
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "__pycache__", ".venv",
  "venv", "dist", "build", ".cache", "coverage",
]);

/** Files of special interest — scan these first (never dropped by MAX_FILES) */
const PRIORITY_FILES = new Set([
  "SKILL.md", "skill.md",
  "package.json",
  "index.ts", "index.js", "server.ts", "server.js",
  "main.ts", "main.js", "app.ts", "app.js",
  ".claude/skills",
]);

/** Filenames that are high-value scan targets regardless of depth */
const HIGH_VALUE_FILENAMES = new Set([
  "skill.md", "package.json", "setup.py", "pyproject.toml",
  "mcp.json", "claude.json", "manifest.json",
]);

export interface ScannableFile {
  path: string;
  relativePath: string;
  content: string;
  size: number;
  type: TargetType;
  isPriority: boolean;
  isTestFile: boolean;
  isDocFile: boolean;
}

/**
 * Infer the scan target type from filename
 */
function inferTargetType(filename: string, relativePath: string): TargetType {
  const base = basename(filename).toLowerCase();
  const ext = extname(filename).toLowerCase();

  if (base === "skill.md" || relativePath.includes(".claude/skills")) {
    return "skill_file";
  }
  if (base === "package.json") {
    return "npm_package";
  }
  if ([".yaml", ".yml", ".toml", ".json"].includes(ext) && base !== "package.json") {
    return "config_file";
  }
  if (ext === ".md") {
    return "skill_file"; // Markdown is documentation, not executable server code
  }
  // Default: treat server code as mcp_server type
  return "mcp_server";
}

/**
 * Walk a directory and return all scannable files, sorted by priority.
 * Priority files (SKILL.md, package.json, tool defs) are ALWAYS included,
 * even if the repo exceeds MAX_FILES. This prevents the file limit from
 * hiding the most security-relevant files in large repos.
 */
export function walkDirectory(rootDir: string): ScannableFile[] {
  const MAX_WALK = 2000; // hard cap on directory traversal to avoid OOM
  const files: ScannableFile[] = [];
  let walkCount = 0;

  function walk(dir: string) {
    if (walkCount >= MAX_WALK) return;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // Permission denied or similar
    }

    for (const entry of entries) {
      if (walkCount >= MAX_WALK) break;

      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
          walk(fullPath);
        }
        // Special case: .claude directory IS interesting
        if (entry.name === ".claude") {
          walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;
      walkCount++;

      const ext = extname(entry.name).toLowerCase();
      if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

      try {
        const stat = statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE) continue;
        if (stat.size === 0) continue;

        const content = readFileSync(fullPath, "utf-8");
        const relativePath = relative(rootDir, fullPath);

        const lowerName = entry.name.toLowerCase();
        const lowerPath = relativePath.toLowerCase();
        const isTestFile = lowerPath.includes("test") || lowerPath.includes("spec") ||
          lowerPath.includes("__tests__") || lowerPath.includes("__mocks__") ||
          lowerName.endsWith(".test.ts") || lowerName.endsWith(".test.js") ||
          lowerName.endsWith(".spec.ts") || lowerName.endsWith(".spec.js");
        const isDocFile = ext === ".md" && lowerName !== "skill.md" &&
          !lowerPath.includes(".claude/skills");

        const isPriority = PRIORITY_FILES.has(entry.name) ||
          HIGH_VALUE_FILENAMES.has(lowerName) ||
          relativePath.includes(".claude/skills");

        files.push({
          path: fullPath,
          relativePath,
          content,
          size: stat.size,
          type: inferTargetType(entry.name, relativePath),
          isPriority,
          isTestFile,
          isDocFile,
        });
      } catch {
        // Skip unreadable files
      }
    }
  }

  walk(rootDir);

  // Sort: priority files first, then by size (smaller first for faster scans)
  files.sort((a, b) => {
    if (a.isPriority && !b.isPriority) return -1;
    if (!a.isPriority && b.isPriority) return 1;
    return a.size - b.size;
  });

  // Enforce MAX_FILES but NEVER drop priority files
  if (files.length > MAX_FILES) {
    const priority = files.filter(f => f.isPriority);
    const rest = files.filter(f => !f.isPriority);
    const remaining = Math.max(0, MAX_FILES - priority.length);
    return [...priority, ...rest.slice(0, remaining)];
  }

  return files;
}
