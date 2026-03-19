/**
 * Upload Session Manager — temp directory lifecycle for file uploads
 */

import { mkdtempSync, rmSync, existsSync, readdirSync, statSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { randomBytes } from "crypto";

const SESSION_PREFIX = "agentcanary-upload-";
const STALE_THRESHOLD_MS = 5 * 60 * 1000;

export interface UploadSession {
  id: string;
  dir: string;
  filename: string;
  format: string;
  createdAt: number;
  scanning: boolean;
  validation?: Record<string, unknown>;
}

const sessions = new Map<string, UploadSession>();

export function createSession(filename: string, format: string): UploadSession {
  const id = `upload-${Date.now()}-${randomBytes(4).toString("hex")}`;
  const dir = mkdtempSync(join(tmpdir(), SESSION_PREFIX));
  const session: UploadSession = {
    id, dir, filename, format, createdAt: Date.now(), scanning: false,
  };
  sessions.set(id, session);
  return session;
}

export function getSession(id: string): UploadSession | null {
  const session = sessions.get(id);
  if (!session) return null;
  if (!existsSync(session.dir)) {
    sessions.delete(id);
    return null;
  }
  return session;
}

export function markScanning(id: string): void {
  const session = sessions.get(id);
  if (session) session.scanning = true;
}

export function cleanupSession(id: string): void {
  const session = sessions.get(id);
  if (session) {
    if (existsSync(session.dir)) {
      rmSync(session.dir, { recursive: true, force: true });
    }
    sessions.delete(id);
  }
}

export function cleanupStaleSessionsSync(): number {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, session] of sessions) {
    if (session.scanning) continue;
    if (now - session.createdAt > STALE_THRESHOLD_MS) {
      cleanupSession(id);
      cleaned++;
    }
  }
  try {
    const tmpBase = tmpdir();
    const entries = readdirSync(tmpBase);
    for (const entry of entries) {
      if (entry.startsWith(SESSION_PREFIX)) {
        const dirPath = join(tmpBase, entry);
        try {
          const stat = statSync(dirPath);
          if (now - stat.mtimeMs > STALE_THRESHOLD_MS) {
            rmSync(dirPath, { recursive: true, force: true });
            cleaned++;
          }
        } catch {}
      }
    }
  } catch {}
  return cleaned;
}
