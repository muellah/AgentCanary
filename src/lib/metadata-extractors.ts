/**
 * Metadata Extractors — derive behavioral signals from code content.
 * Extracts: install invasiveness, network behavior, auth patterns.
 * These are Tier 2 signals that don't require GitHub API access.
 */

import type { MetadataSignals } from "@/engine/types";

const DOTFILE_PATTERNS = [
  /\.bashrc/gi,
  /\.zshrc/gi,
  /\.bash_profile/gi,
  /\.profile/gi,
  /\.zprofile/gi,
];

const TOOL_CONFIG_PATTERNS = [
  /\.claude\//gi,
  /\.cursor\//gi,
  /\.vscode\//gi,
  /\.codex/gi,
  /\.gemini/gi,
  /\.zed/gi,
];

const EXTERNAL_PATH_PATTERNS = [
  /\/usr\/local\//gi,
  /\/opt\//gi,
  /\/etc\//gi,
  /~\//g,
  /\$HOME\//gi,
  /process\.env\.HOME/gi,
  /os\.homedir\(\)/gi,
];

const CORS_WILDCARD = /['"]?\*['"]?\s*(?:\/\/.*cors|.*access-control-allow-origin)/gi;
const CORS_HEADER_SET = /['"](Access-Control-Allow-Origin|cors)['"]\s*[,:]\s*['"]\*['"]/gi;
const LOCALHOST_BIND = /(?:listen|bind|host)\s*[\(:]?\s*['"]?(0\.0\.0\.0|127\.0\.0\.1|localhost)['"]?/gi;

const PHONE_HOME_PATTERNS = [
  /setInterval\s*\(\s*(?:async\s*)?\(\)\s*=>\s*(?:.*fetch|.*http|.*request)/gi,
  /setTimeout\s*\(\s*(?:async\s*)?\(\)\s*=>\s*(?:.*fetch|.*http|.*request)/gi,
  /(?:check|version|update).*(?:fetch|http\.get|axios\.get|request)\s*\(/gi,
  /api\.github\.com/gi,
];

const DANGEROUS_ENDPOINT_PATTERNS = [
  { pattern: /(?:process|pid)[\-_.]?kill/gi, name: "process-kill" },
  { pattern: /(?:file|fs)[\-_.]?(?:delete|remove|unlink)/gi, name: "file-delete" },
  { pattern: /(?:shell|exec|spawn|system)\s*\(/gi, name: "shell-exec" },
  { pattern: /(?:shutdown|restart|reboot)/gi, name: "system-control" },
];

interface FileContent {
  filename: string;
  content: string;
}

export function extractInstallInvasiveness(
  files: FileContent[],
): MetadataSignals["installInvasiveness"] {
  const externalPaths = new Set<string>();
  const dotfilesModified = new Set<string>();
  const toolConfigsModified = new Set<string>();

  for (const file of files) {
    const content = file.content;

    for (const pattern of DOTFILE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) dotfilesModified.add(match[0]);
      }
    }

    for (const pattern of TOOL_CONFIG_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) toolConfigsModified.add(match[0]);
      }
    }

    for (const pattern of EXTERNAL_PATH_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const match = content.match(pattern);
        if (match) externalPaths.add(match[0]);
      }
    }
  }

  return {
    externalPaths: [...externalPaths],
    dotfilesModified: [...dotfilesModified],
    toolConfigsModified: [...toolConfigsModified],
  };
}

export function extractNetworkBehavior(
  files: FileContent[],
): MetadataSignals["network"] {
  const outboundDomains = new Set<string>();
  let phoneHome = false;
  let corsPolicy: string | null = null;
  let localhostBinding: string | null = null;

  const domainPattern = /(?:fetch|get|post|put|request|axios)\s*\(\s*[`'"](https?:\/\/([^/'"` ]+))/gi;

  for (const file of files) {
    const content = file.content;

    domainPattern.lastIndex = 0;
    let match;
    while ((match = domainPattern.exec(content)) !== null) {
      if (match[2]) outboundDomains.add(match[2]);
    }

    CORS_WILDCARD.lastIndex = 0;
    CORS_HEADER_SET.lastIndex = 0;
    if (CORS_WILDCARD.test(content) || CORS_HEADER_SET.test(content)) {
      corsPolicy = "*";
    }

    LOCALHOST_BIND.lastIndex = 0;
    const bindMatch = LOCALHOST_BIND.exec(content);
    if (bindMatch) {
      localhostBinding = bindMatch[1];
    }

    for (const pattern of PHONE_HOME_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        phoneHome = true;
        break;
      }
    }
  }

  return {
    outboundDomains: [...outboundDomains],
    phoneHome,
    corsPolicy,
    localhostBinding,
  };
}

export function extractAuthSignals(
  files: FileContent[],
): MetadataSignals["auth"] {
  const dangerousEndpoints: { name: string; authenticated: boolean }[] = [];

  for (const file of files) {
    const content = file.content;

    for (const { pattern, name } of DANGEROUS_ENDPOINT_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const lines = content.split("\n");
        let hasAuth = false;
        for (let i = 0; i < lines.length; i++) {
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            const context = lines.slice(Math.max(0, i - 20), i + 20).join("\n");
            if (/auth|middleware|bearer|token|session|cookie/i.test(context)) {
              hasAuth = true;
            }
          }
        }
        dangerousEndpoints.push({ name, authenticated: hasAuth });
      }
    }
  }

  return { dangerousEndpoints };
}

export function extractDependencySignals(
  packageJsonContent: string | null,
): MetadataSignals["dependencies"] {
  if (!packageJsonContent) {
    return { total: 0, installHooks: [] };
  }

  try {
    const pkg = JSON.parse(packageJsonContent);
    const deps = Object.keys(pkg.dependencies || {}).length +
                 Object.keys(pkg.devDependencies || {}).length;

    const hookNames = ["preinstall", "install", "postinstall", "prepare", "prepublish"];
    const installHooks = hookNames.filter(
      h => pkg.scripts && typeof pkg.scripts[h] === "string"
    );

    return { total: deps, installHooks };
  } catch {
    return { total: 0, installHooks: [] };
  }
}

export function extractCodeMetadata(
  files: FileContent[],
  packageJsonContent: string | null,
): Pick<MetadataSignals, "installInvasiveness" | "network" | "auth" | "dependencies"> {
  return {
    installInvasiveness: extractInstallInvasiveness(files),
    network: extractNetworkBehavior(files),
    auth: extractAuthSignals(files),
    dependencies: extractDependencySignals(packageJsonContent),
  };
}
