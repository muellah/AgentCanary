/**
 * LLM API Integration — Provides the semantic checker's apiCall function
 * Supports both OpenAI and Anthropic (Claude) APIs.
 * Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env.local
 * OpenAI is checked first (cheaper for high-volume scanning).
 */

import type { SemanticApiCall } from "@/engine/checkers";

/**
 * Create a semantic API call function for the scan engine.
 * Tries OpenAI first (gpt-4o-mini is fast + cheap), falls back to Anthropic.
 * Returns undefined if no API key is configured (semantic rules will be skipped).
 */
export function createSemanticApiCall(): SemanticApiCall | undefined {
  const openaiKey = process.env.OPENAI_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;

  if (openaiKey) {
    return createOpenAICall(openaiKey);
  }
  if (anthropicKey) {
    return createAnthropicCall(anthropicKey);
  }
  return undefined;
}

function createOpenAICall(apiKey: string): SemanticApiCall {
  // Dynamic import to avoid bundling both SDKs
  const OpenAI = require("openai").default;
  const client = new OpenAI({ apiKey });

  return async (model: string, systemPrompt: string, userContent: string): Promise<string> => {
    const modelMap: Record<string, string> = {
      "claude-sonnet": "gpt-4o-mini",
      "claude-haiku": "gpt-4o-mini",
    };
    const modelId = modelMap[model] || "gpt-4o-mini";

    const response = await client.chat.completions.create({
      model: modelId,
      max_tokens: 500,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent },
      ],
    });

    return response.choices[0]?.message?.content || "{}";
  };
}

function createAnthropicCall(apiKey: string): SemanticApiCall {
  const Anthropic = require("@anthropic-ai/sdk").default;
  const client = new Anthropic({ apiKey });

  return async (model: string, systemPrompt: string, userContent: string): Promise<string> => {
    const modelMap: Record<string, string> = {
      "claude-sonnet": "claude-sonnet-4-20250514",
      "claude-haiku": "claude-haiku-4-20250414",
    };
    const modelId = modelMap[model] || "claude-sonnet-4-20250514";

    const response = await client.messages.create({
      model: modelId,
      max_tokens: 500,
      system: systemPrompt,
      messages: [{ role: "user", content: userContent }],
    });

    const textBlock = response.content.find((b: { type: string }) => b.type === "text");
    return textBlock ? (textBlock as { text: string }).text : "{}";
  };
}
