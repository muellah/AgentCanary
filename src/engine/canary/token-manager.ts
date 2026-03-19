/**
 * Canary Token Manager
 * Central class for generating, embedding, and checking canary tokens
 */

import crypto from "node:crypto";
import type {
  CanaryToken,
  CanaryType,
  CanaryActivation,
  PromptCanaryResult,
} from "./types";

const DEFAULT_TOKEN_BYTES = 8; // 16 hex characters

export class CanaryTokenManager {
  private tokens: Map<string, CanaryToken> = new Map();

  /**
   * Generate a new canary token of the specified type
   */
  generate(
    type: CanaryType,
    options: { tokenBytes?: number; metadata?: Record<string, unknown> } = {}
  ): CanaryToken {
    const bytes = options.tokenBytes ?? DEFAULT_TOKEN_BYTES;
    const value = crypto.randomBytes(bytes).toString("hex");
    const id = `canary-${type}-${crypto.randomBytes(4).toString("hex")}`;

    const token: CanaryToken = {
      id,
      type,
      value,
      formatted: this.formatToken(type, value),
      createdAt: new Date().toISOString(),
      status: "active",
      metadata: options.metadata,
    };

    this.tokens.set(id, token);
    return token;
  }

  /**
   * Format a raw token value for embedding based on its type
   */
  formatToken(type: CanaryType, value: string): string {
    switch (type) {
      case "prompt_injection":
        return `<!-- ${value} -->`;
      case "tool_pin":
        return value; // Raw hash, not embedded
      case "credential":
        return `AKIA${value.toUpperCase().slice(0, 16)}`;
      case "filesystem":
        return `.canary-${value.slice(0, 8)}`;
      case "network":
        return `https://canary.agentcanary.dev/${value}`;
      default:
        return value;
    }
  }

  /**
   * Embed a canary token into content
   * Returns the content with the canary injected at the specified position
   */
  embed(
    content: string,
    token: CanaryToken,
    position: "prepend" | "append" | "inline" = "append"
  ): string {
    switch (position) {
      case "prepend":
        return `${token.formatted}\n${content}`;
      case "append":
        return `${content}\n${token.formatted}`;
      case "inline":
        return `${content} ${token.formatted}`;
    }
  }

  /**
   * Check if a canary token appears in the given output
   * Used for prompt leak detection
   */
  checkLeak(token: CanaryToken, output: string): PromptCanaryResult {
    const found = output.includes(token.value);
    return {
      triggered: found,
      mode: "leak",
      token: token.value,
      detail: found
        ? `Canary token "${token.value}" was found in the output — prompt content was leaked`
        : `Canary token was not found in output — no leak detected`,
    };
  }

  /**
   * Check if a canary token is missing from the given output
   * Used for prompt hijack detection (token was instructed but not present)
   */
  checkHijack(token: CanaryToken, output: string): PromptCanaryResult {
    const found = output.includes(token.value);
    return {
      triggered: !found,
      mode: "hijack",
      token: token.value,
      detail: !found
        ? `Canary token "${token.value}" was NOT found in output — goal was likely hijacked`
        : `Canary token was present in output — no hijack detected`,
    };
  }

  /**
   * Build a CanaryActivation from a prompt canary result
   */
  buildActivation(
    token: CanaryToken,
    result: PromptCanaryResult
  ): CanaryActivation | null {
    if (!result.triggered) return null;

    const trigger =
      result.mode === "leak"
        ? {
            kind: "prompt_leak" as const,
            token: token.value,
            location: "output",
          }
        : {
            kind: "prompt_hijack" as const,
            token: token.value,
            checkedOutput: "(truncated)",
          };

    return {
      canaryId: token.id,
      type: "prompt_injection",
      detectedAt: new Date().toISOString(),
      trigger,
      severity: result.mode === "leak" ? "high" : "critical",
      description: result.detail,
    };
  }

  /**
   * Retrieve a previously generated token by ID
   */
  getToken(id: string): CanaryToken | undefined {
    return this.tokens.get(id);
  }

  /**
   * List all active tokens
   */
  getActiveTokens(): CanaryToken[] {
    return Array.from(this.tokens.values()).filter(
      (t) => t.status === "active"
    );
  }
}
