/**
 * SARIF v2.1.0 Formatter — Converts scan findings to SARIF output
 */

import type { Finding, Severity, SARIFOutput } from "./types";

export class SARIFFormatter {
  private schemaUri =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

  format(
    findings: Finding[],
    meta: { targetUri?: string; startTime?: string; endTime?: string } = {}
  ): SARIFOutput {
    const ruleMap = new Map<string, unknown>();
    const results: unknown[] = [];

    for (const finding of findings) {
      if (!ruleMap.has(finding.ruleId)) {
        ruleMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.ruleTitle,
          shortDescription: { text: finding.ruleTitle },
          fullDescription: { text: finding.ruleDescription || "" },
          defaultConfiguration: {
            level: this.severityToLevel(finding.severity),
          },
          properties: {
            tags: finding.tags || [],
            category: finding.category,
            confidence: finding.confidence,
          },
        });
      }

      results.push({
        ruleId: finding.ruleId,
        level: this.severityToLevel(finding.severity),
        message: { text: finding.reportTitle },
        locations: finding.location
          ? [
              {
                physicalLocation: {
                  artifactLocation: { uri: meta.targetUri || "unknown" },
                  region: finding.location.line
                    ? {
                        startLine: finding.location.line,
                        snippet: { text: finding.location.snippet || "" },
                      }
                    : undefined,
                },
              },
            ]
          : [],
        properties: {
          confidence: finding.confidence,
          category: finding.category,
          matchDetails: finding.matches,
          recommendation: finding.recommendation,
        },
      });
    }

    return {
      $schema: this.schemaUri,
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "AgentCanary",
              version: "0.1.0",
              informationUri: "https://agentcanary.dev",
              rules: Array.from(ruleMap.values()),
            },
          },
          results,
          invocations: [
            {
              executionSuccessful: true,
              startTimeUtc: meta.startTime || new Date().toISOString(),
              endTimeUtc: meta.endTime || new Date().toISOString(),
            },
          ],
        },
      ],
    };
  }

  private severityToLevel(severity: Severity): string {
    const map: Record<Severity, string> = {
      critical: "error",
      high: "error",
      medium: "warning",
      low: "note",
      info: "none",
    };
    return map[severity] || "warning";
  }
}
