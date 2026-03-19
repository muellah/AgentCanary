import { describe, it, expect } from "vitest";
import {
  ACCEPTED_EXTENSIONS,
  MAX_SIZES,
  BLOCKED_EXTENSIONS,
  BLOCKED_MIMES,
  isAcceptedExtension,
  getMaxSize,
  isBinaryContent,
  isValidUtf8,
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

describe("Layer 3: Content safety", () => {
  it("detects ELF binary magic bytes", () => {
    const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]);
    expect(isBinaryContent(elfHeader)).toBe(true);
  });

  it("detects PE/MZ executable magic bytes", () => {
    const peHeader = Buffer.from([0x4d, 0x5a, 0x90, 0x00]);
    expect(isBinaryContent(peHeader)).toBe(true);
  });

  it("detects Mach-O binary magic bytes", () => {
    const machoHeader = Buffer.from([0xcf, 0xfa, 0xed, 0xfe]);
    expect(isBinaryContent(machoHeader)).toBe(true);
  });

  it("detects PDF magic bytes", () => {
    const pdfHeader = Buffer.from("%PDF-1.4 fake content");
    expect(isBinaryContent(pdfHeader)).toBe(true);
  });

  it("passes normal UTF-8 text", () => {
    const text = Buffer.from("# My SKILL\n\nDo something useful.");
    expect(isBinaryContent(text)).toBe(false);
  });

  it("validates UTF-8 encoding", () => {
    const validUtf8 = Buffer.from("Hello world 🌍");
    expect(isValidUtf8(validUtf8)).toBe(true);
  });

  it("rejects invalid UTF-8 bytes", () => {
    const invalidUtf8 = Buffer.from([0x80, 0x81, 0x82, 0xff, 0xfe]);
    expect(isValidUtf8(invalidUtf8)).toBe(false);
  });
});
