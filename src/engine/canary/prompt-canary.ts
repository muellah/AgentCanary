/**
 * Prompt Injection Canary — Leak & Hijack Detection
 *
 * Generates unique canary tokens embedded into prompts/content.
 * - Leak mode: if the token appears in output, the prompt was leaked
 * - Hijack mode: if the token is missing from output, the goal was hijacked
 */

import type {
  CanaryToken,
  CanaryActivation,
  CanaryMode,
  PromptCanaryOptions,
  PromptCanaryResult,
} from "./types";
import { CanaryTokenManager } from "./token-manager";

export class PromptCanary {
  private manager: CanaryTokenManager;

  constructor(manager?: CanaryTokenManager) {
    this.manager = manager ?? new CanaryTokenManager();
  }

  /**
   * Generate a prompt canary token and embed it into content
   */
  generate(
    content: string,
    options: PromptCanaryOptions = { mode: "leak" }
  ): { content: string; token: CanaryToken } {
    const token = this.manager.generate("prompt_injection", {
      tokenBytes: options.tokenBytes,
      metadata: { mode: options.mode },
    });

    // Override format if custom formatter provided
    if (options.formatFn) {
      token.formatted = options.formatFn(token.value);
    }

    const embeddedContent = this.embedForMode(content, token, options.mode);
    return { content: embeddedContent, token };
  }

  /**
   * Check output against a canary token
   */
  check(token: CanaryToken, output: string): PromptCanaryResult {
    const mode = (token.metadata?.mode as CanaryMode) ?? "leak";
    return mode === "leak"
      ? this.manager.checkLeak(token, output)
      : this.manager.checkHijack(token, output);
  }

  /**
   * Generate, embed, and return a checker function (convenience method)
   * Returns an object with the modified content and a check function
   */
  createProbe(
    content: string,
    options: PromptCanaryOptions = { mode: "leak" }
  ): {
    content: string;
    token: CanaryToken;
    check: (output: string) => PromptCanaryResult;
    toActivation: (output: string) => CanaryActivation | null;
  } {
    const { content: embedded, token } = this.generate(content, options);

    return {
      content: embedded,
      token,
      check: (output: string) => this.check(token, output),
      toActivation: (output: string) => {
        const result = this.check(token, output);
        return this.manager.buildActivation(token, result);
      },
    };
  }

  /**
   * Run a leak detection test
   * Embeds a hidden canary in content, then checks if it appears in output
   */
  testLeak(content: string, output: string): PromptCanaryResult {
    const { token } = this.generate(content, { mode: "leak" });
    // In real usage, the content would be sent to an LLM first.
    // Here we check the provided output against the generated token.
    return this.manager.checkLeak(token, output);
  }

  /**
   * Run a hijack detection test
   * Instructs to include a canary in response, then checks if it's present
   */
  testHijack(content: string, output: string): PromptCanaryResult {
    const { token } = this.generate(content, { mode: "hijack" });
    return this.manager.checkHijack(token, output);
  }

  // ---- Private helpers ----

  /**
   * Embed token into content based on mode
   * - Leak mode: hide the token so it should NOT appear in output
   * - Hijack mode: instruct the model to include the token in output
   */
  private embedForMode(
    content: string,
    token: CanaryToken,
    mode: CanaryMode
  ): string {
    if (mode === "leak") {
      // Hide the canary in an HTML comment — if LLM outputs it, prompt was leaked
      return this.manager.embed(content, token, "append");
    } else {
      // Hijack mode — instruct the model to echo the token
      const instruction = `\n[IMPORTANT: Your response MUST contain the verification code: ${token.value}]\n`;
      return `${content}${instruction}`;
    }
  }
}
