import { describe, it, expect, afterEach } from "vitest";
import {
  createSession,
  getSession,
  cleanupSession,
  cleanupStaleSessionsSync,
  markScanning,
} from "@/lib/upload-session";
import { existsSync } from "fs";

describe("Upload session manager", () => {
  const sessionIds: string[] = [];

  afterEach(() => {
    for (const id of sessionIds) {
      try { cleanupSession(id); } catch {}
    }
    sessionIds.length = 0;
  });

  it("creates a session with a temp directory", () => {
    const session = createSession("test.md", "skill_md");
    sessionIds.push(session.id);
    expect(session.id).toMatch(/^upload-/);
    expect(existsSync(session.dir)).toBe(true);
    expect(session.format).toBe("skill_md");
  });

  it("retrieves a created session", () => {
    const session = createSession("test.zip", "zip_plugin");
    sessionIds.push(session.id);
    const retrieved = getSession(session.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.dir).toBe(session.dir);
  });

  it("returns null for unknown session ID", () => {
    expect(getSession("upload-nonexistent")).toBeNull();
  });

  it("cleans up session directory", () => {
    const session = createSession("test.md", "skill_md");
    sessionIds.push(session.id);
    expect(existsSync(session.dir)).toBe(true);
    cleanupSession(session.id);
    expect(existsSync(session.dir)).toBe(false);
  });

  it("cleanupStaleSessionsSync removes sessions older than 5 minutes", () => {
    const session = createSession("stale.md", "skill_md");
    sessionIds.push(session.id);
    const retrieved = getSession(session.id);
    expect(retrieved).not.toBeNull();
    (retrieved as any).createdAt = Date.now() - 6 * 60 * 1000;
    const cleaned = cleanupStaleSessionsSync();
    expect(cleaned).toBeGreaterThanOrEqual(1);
    expect(getSession(session.id)).toBeNull();
  });

  it("cleanupStaleSessionsSync skips sessions that are scanning", () => {
    const session = createSession("scanning.md", "skill_md");
    sessionIds.push(session.id);
    const retrieved = getSession(session.id);
    (retrieved as any).createdAt = Date.now() - 6 * 60 * 1000;
    markScanning(session.id);
    cleanupStaleSessionsSync();
    const stillExists = getSession(session.id);
    expect(stillExists).not.toBeNull();
    expect(existsSync(session.dir)).toBe(true);
  });

  it("stores validation data on session", () => {
    const session = createSession("test.md", "skill_md");
    sessionIds.push(session.id);
    const validationData = {
      format: "skill_md" as const,
      filename: "test.md",
      size: 1024,
      checks: { binaryContent: "pass" as const, skillContent: "pass" as const, encoding: "pass" as const },
    };
    session.validation = validationData;
    const retrieved = getSession(session.id);
    expect(retrieved!.validation).toEqual(validationData);
  });
});
