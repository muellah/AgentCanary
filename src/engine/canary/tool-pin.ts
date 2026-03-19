/**
 * Tool Pin — Rug-Pull Detection via Tool Description Hashing
 *
 * Hashes tool definitions at scan time and stores them in a local
 * pin file. On re-scan, compares hashes to detect rug-pull changes
 * where a tool's definition silently changes after initial trust.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type {
  ToolPin,
  PinFile,
  CanaryActivation,
  ToolPinTrigger,
} from "./types";

const PIN_FILE_VERSION = "1.0.0";
const DEFAULT_PIN_DIR = ".agentcanary";
const DEFAULT_PIN_FILE = "pins.json";

export class ToolPinManager {
  private pinDir: string;
  private pinFilePath: string;

  constructor(options: { pinDir?: string } = {}) {
    this.pinDir = options.pinDir ?? DEFAULT_PIN_DIR;
    this.pinFilePath = path.join(this.pinDir, DEFAULT_PIN_FILE);
  }

  /**
   * Compute SHA-256 hash of a canonical JSON representation of a tool definition
   */
  hashToolDefinition(definition: Record<string, unknown>): string {
    const canonical = JSON.stringify(definition, Object.keys(definition).sort());
    return crypto.createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Pin a set of tool definitions — write hashes to the pin file
   * Returns the created pins
   */
  async pinTools(
    tools: { toolId: string; definition: Record<string, unknown> }[]
  ): Promise<ToolPin[]> {
    const pinFile = await this.loadPinFile();
    const pins: ToolPin[] = [];

    for (const tool of tools) {
      const hash = this.hashToolDefinition(tool.definition);
      const pin: ToolPin = {
        toolId: tool.toolId,
        hash,
        pinnedAt: new Date().toISOString(),
        definition: tool.definition,
      };
      pinFile.pins[tool.toolId] = pin;
      pins.push(pin);
    }

    pinFile.updatedAt = new Date().toISOString();
    await this.savePinFile(pinFile);
    return pins;
  }

  /**
   * Verify tool definitions against stored pins
   * Returns activations for any tools whose definitions changed
   */
  async verifyTools(
    tools: { toolId: string; definition: Record<string, unknown> }[]
  ): Promise<{
    matches: string[];
    mismatches: CanaryActivation[];
    newTools: string[];
  }> {
    const pinFile = await this.loadPinFile();
    const matches: string[] = [];
    const mismatches: CanaryActivation[] = [];
    const newTools: string[] = [];

    for (const tool of tools) {
      const existingPin = pinFile.pins[tool.toolId];
      if (!existingPin) {
        newTools.push(tool.toolId);
        continue;
      }

      const currentHash = this.hashToolDefinition(tool.definition);
      if (currentHash === existingPin.hash) {
        matches.push(tool.toolId);
      } else {
        const trigger: ToolPinTrigger = {
          kind: "tool_pin_mismatch",
          toolId: tool.toolId,
          originalHash: existingPin.hash,
          currentHash,
        };

        mismatches.push({
          canaryId: `pin-${tool.toolId}`,
          type: "tool_pin",
          detectedAt: new Date().toISOString(),
          trigger,
          severity: "critical",
          description:
            `Tool "${tool.toolId}" definition has changed since it was pinned. ` +
            `Original hash: ${existingPin.hash.slice(0, 12)}... ` +
            `Current hash: ${currentHash.slice(0, 12)}... ` +
            `This may indicate a rug-pull attack.`,
        });
      }
    }

    return { matches, mismatches, newTools };
  }

  /**
   * Get the stored pin for a specific tool
   */
  async getPin(toolId: string): Promise<ToolPin | null> {
    const pinFile = await this.loadPinFile();
    return pinFile.pins[toolId] ?? null;
  }

  /**
   * Remove a pin for a specific tool
   */
  async removePin(toolId: string): Promise<boolean> {
    const pinFile = await this.loadPinFile();
    if (!(toolId in pinFile.pins)) return false;
    delete pinFile.pins[toolId];
    pinFile.updatedAt = new Date().toISOString();
    await this.savePinFile(pinFile);
    return true;
  }

  /**
   * Get all stored pins
   */
  async getAllPins(): Promise<Record<string, ToolPin>> {
    const pinFile = await this.loadPinFile();
    return pinFile.pins;
  }

  // ---- Private helpers ----

  private async loadPinFile(): Promise<PinFile> {
    try {
      const raw = await fs.readFile(this.pinFilePath, "utf-8");
      return JSON.parse(raw) as PinFile;
    } catch {
      // File doesn't exist yet — return empty pin file
      return {
        version: PIN_FILE_VERSION,
        updatedAt: new Date().toISOString(),
        pins: {},
      };
    }
  }

  private async savePinFile(pinFile: PinFile): Promise<void> {
    await fs.mkdir(this.pinDir, { recursive: true });
    await fs.writeFile(
      this.pinFilePath,
      JSON.stringify(pinFile, null, 2),
      "utf-8"
    );
  }
}
