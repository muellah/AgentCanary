/**
 * Confidence Calculator — combines code scan findings with metadata signals
 * to produce a confidence score (0.0–1.0) and human-readable caveats.
 *
 * Replaces the old calculateVerdictConfidence() in scan-orchestrator.ts.
 */

import type { Finding, MetadataSignals, Caveat } from "./types";

/** Check if a rule ID indicates intent (not just capability) */
function isIntentRule(ruleId: string): boolean {
  const INTENT_RULES = new Set([
    "ACR-S-004", "ACR-S-005", "ACR-S-006", "ACR-S-020",
    "ACR-S-019", "ACR-S-002", "ACR-S-017", "ACR-S-010",
    "ACR-S-018", "ACR-S-022", "ACR-S-015", "ACR-S-023",
    "ACR-S-001", "ACR-S-028", "ACR-S-027", "ACR-S-016",
    "ACR-M-001", "ACR-M-002", "ACR-M-003", "ACR-M-004",
    "ACR-M-005", "ACR-M-006", "ACR-M-007",
    "ACR-C-001", "ACR-C-002", "ACR-C-003",
    "ACR-V-001", "ACR-V-002", "ACR-V-003",
  ]);
  return INTENT_RULES.has(ruleId);
}

export interface ConfidenceResult {
  confidence: number;
  caveats: Caveat[];
}

function calculateBaseConfidence(findings: Finding[], shortCircuit: boolean): number {
  if (shortCircuit) return 0.95;
  if (findings.length === 0) return 0.60;

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const intentCount = findings.filter(f => isIntentRule(f.ruleId)).length;

  if (criticalCount >= 2 || (criticalCount >= 1 && intentCount >= 1)) return 0.90;
  if (highCount >= 3) return 0.80;
  if (findings.length <= 2) return 0.45;
  return 0.55;
}

function applyMetadataAdjustments(
  base: number,
  metadata: MetadataSignals | null | undefined,
): ConfidenceResult {
  if (!metadata) {
    return { confidence: base, caveats: [] };
  }

  let adj = 0;
  const caveats: Caveat[] = [];

  // Author credibility
  if (metadata.author) {
    const { type, accountAge, publicRepos } = metadata.author;
    if (type === "Organization" || (accountAge > 730 && publicRepos > 20)) {
      adj += 0.08;
    } else if (accountAge < 180 && publicRepos <= 2) {
      adj -= 0.10;
      caveats.push({ dimension: "author_credibility", severity: "warning", text: "Author account is new with no track record" });
    }
  }

  // Repo vitals
  if (metadata.repo) {
    if (metadata.repo.age > 365) {
      adj += 0.05;
    } else if (metadata.repo.age < 90) {
      adj -= 0.08;
      caveats.push({ dimension: "repo_age", severity: "warning", text: "Repository is less than 90 days old" });
    }

    if (metadata.repo.license) {
      const permissive = ["mit", "apache-2.0", "isc", "bsd-2-clause", "bsd-3-clause", "unlicense"];
      if (permissive.includes(metadata.repo.license.toLowerCase())) {
        adj += 0.03;
      }
    } else {
      adj -= 0.05;
      caveats.push({ dimension: "license", severity: "info", text: "No license file found" });
    }

    if (metadata.repo.contributorCount !== undefined) {
      if (metadata.repo.contributorCount > 3) {
        adj += 0.05;
      } else if (metadata.repo.contributorCount <= 1) {
        adj -= 0.05;
        caveats.push({ dimension: "contributor_concentration", severity: "info", text: "Single-author project" });
      }
    }

    if (metadata.repo.starsPerDay !== undefined) {
      if (metadata.repo.starsPerDay > 50 && metadata.repo.age < 30) {
        adj -= 0.10;
        caveats.push({ dimension: "star_velocity", severity: "warning", text: "Star growth pattern appears inorganic" });
      }
    }
  }

  // Dependencies
  if (metadata.dependencies) {
    if (metadata.dependencies.installHooks.length === 0) {
      adj += 0.03;
    } else {
      adj -= 0.05;
      caveats.push({ dimension: "install_hooks", severity: "warning", text: `Package has install lifecycle hooks: ${metadata.dependencies.installHooks.join(", ")}` });
    }

    if (metadata.dependencies.knownCves) {
      const criticalCves = metadata.dependencies.knownCves.filter(c => c.severity === "critical" || c.severity === "high");
      if (criticalCves.length > 0) {
        adj -= 0.15;
        caveats.push({ dimension: "known_cves", severity: "critical", text: `${criticalCves.length} critical/high CVEs in dependencies` });
      } else if (metadata.dependencies.knownCves.length === 0) {
        adj += 0.05;
      }
    }
  }

  // Install invasiveness
  if (metadata.installInvasiveness) {
    const totalExternal = metadata.installInvasiveness.externalPaths.length + metadata.installInvasiveness.dotfilesModified.length + metadata.installInvasiveness.toolConfigsModified.length;
    if (totalExternal <= 1) {
      adj += 0.03;
    } else if (totalExternal >= 5) {
      adj -= 0.10;
      caveats.push({ dimension: "install_invasiveness", severity: "warning", text: `Modifies ${totalExternal} files outside project directory` });
    }
  }

  // Network behavior
  if (metadata.network) {
    if (metadata.network.phoneHome) {
      adj -= 0.07;
      caveats.push({ dimension: "phone_home", severity: "warning", text: "Phones home on startup without opt-out" });
    }
    if (metadata.network.corsPolicy === "*") {
      adj -= 0.08;
      caveats.push({ dimension: "cors_policy", severity: "warning", text: "CORS wildcard (*) on local HTTP server" });
    }
    if (metadata.network.outboundDomains.length > 0 && !metadata.network.phoneHome && metadata.network.corsPolicy !== "*") {
      adj += 0.05;
    }
  }

  // Auth & access control
  if (metadata.auth) {
    const unauthDangerous = metadata.auth.dangerousEndpoints.filter(e => !e.authenticated);
    if (unauthDangerous.length > 0) {
      adj -= 0.12;
      for (const ep of unauthDangerous) {
        caveats.push({ dimension: "auth_endpoints", severity: "critical", text: `Unauthenticated endpoint: ${ep.name}` });
      }
    } else if (metadata.auth.dangerousEndpoints.length > 0) {
      adj += 0.03;
    }
  }

  const confidence = Math.max(0.10, Math.min(0.98, base + adj));
  return { confidence, caveats };
}

export function calculateConfidence(
  findings: Finding[],
  shortCircuit: boolean,
  metadata?: MetadataSignals | null,
): ConfidenceResult {
  const base = calculateBaseConfidence(findings, shortCircuit);
  return applyMetadataAdjustments(base, metadata);
}
