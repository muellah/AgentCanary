import { describe, it, expect } from "vitest";
import {
  ACCEPTED_EXTENSIONS,
  MAX_SIZES,
  BLOCKED_EXTENSIONS,
  BLOCKED_MIMES,
  isAcceptedExtension,
  getMaxSize,
} from "@/lib/upload-validator";

describe("Client-side validation constants", () => {
  it("accepts .md files", () => {
    expect(isAcceptedExtension(".md")).toBe(true);
  });

  it("accepts .zip files", () => {
    expect(isAcceptedExtension(".zip")).toBe(true);
  });

  it("accepts .json files", () => {
    expect(isAcceptedExtension(".json")).toBe(true);
  });

  it("accepts .yaml and .yml files", () => {
    expect(isAcceptedExtension(".yaml")).toBe(true);
    expect(isAcceptedExtension(".yml")).toBe(true);
  });

  it("rejects unlisted extensions (default deny)", () => {
    expect(isAcceptedExtension(".txt")).toBe(false);
    expect(isAcceptedExtension(".py")).toBe(false);
    expect(isAcceptedExtension(".csv")).toBe(false);
  });

  it("rejects explicitly blocked extensions", () => {
    expect(isAcceptedExtension(".exe")).toBe(false);
    expect(isAcceptedExtension(".dll")).toBe(false);
    expect(isAcceptedExtension(".sh")).toBe(false);
  });

  it("returns correct max sizes per format", () => {
    expect(getMaxSize(".md")).toBe(1024 * 1024);
    expect(getMaxSize(".zip")).toBe(10 * 1024 * 1024);
    expect(getMaxSize(".json")).toBe(1024 * 1024);
    expect(getMaxSize(".yaml")).toBe(512 * 1024);
  });

  it("BLOCKED_MIMES contains known executable MIME types", () => {
    expect(BLOCKED_MIMES.has("application/x-executable")).toBe(true);
    expect(BLOCKED_MIMES.has("application/x-mach-binary")).toBe(true);
    expect(BLOCKED_MIMES.has("application/x-dosexec")).toBe(true);
    expect(BLOCKED_MIMES.has("application/x-msdownload")).toBe(true);
  });
});
