/**
 * GitHub Fetcher — Clones repos to temp directories for scanning
 * Supports github.com URLs, extracts owner/repo, shallow clones
 */

import { simpleGit } from "simple-git";
import { randomBytes } from "crypto";
import { existsSync, mkdirSync, rmSync } from "fs";
import { join } from "path";

const CLONE_TIMEOUT = 30_000; // 30 seconds
const MAX_REPO_SIZE_MB = 100; // Skip repos larger than this

export interface CloneResult {
  success: boolean;
  localPath?: string;
  owner?: string;
  repo?: string;
  error?: string;
  cleanupFn?: () => void;
}

/**
 * Parse a GitHub URL into owner/repo
 * Supports: https://github.com/owner/repo, github.com/owner/repo, owner/repo
 */
export function parseGitHubUrl(input: string): { owner: string; repo: string } | null {
  const cleaned = input.trim().replace(/\/+$/, "").replace(/\.git$/, "");

  // Full URL: https://github.com/owner/repo
  const urlMatch = cleaned.match(
    /(?:https?:\/\/)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/
  );
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2] };
  }

  // Short form: owner/repo
  const shortMatch = cleaned.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }

  return null;
}

/**
 * Shallow clone a GitHub repo to a temporary directory
 */
export async function cloneRepo(githubUrl: string): Promise<CloneResult> {
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) {
    return { success: false, error: `Invalid GitHub URL: ${githubUrl}` };
  }

  const tmpBase = join(process.cwd(), "tmp-scans");
  if (!existsSync(tmpBase)) {
    mkdirSync(tmpBase, { recursive: true });
  }

  const dirName = `${parsed.owner}-${parsed.repo}-${randomBytes(4).toString("hex")}`;
  const localPath = join(tmpBase, dirName);

  const cleanupFn = () => {
    try {
      if (existsSync(localPath)) {
        rmSync(localPath, { recursive: true, force: true });
      }
    } catch {
      // Best effort cleanup
    }
  };

  try {
    const git = simpleGit({ timeout: { block: CLONE_TIMEOUT } });
    const cloneUrl = `https://github.com/${parsed.owner}/${parsed.repo}.git`;

    await git.clone(cloneUrl, localPath, [
      "--depth", "1",
      "--single-branch",
    ]);

    return {
      success: true,
      localPath,
      owner: parsed.owner,
      repo: parsed.repo,
      cleanupFn,
    };
  } catch (err) {
    cleanupFn();
    const msg = (err as Error).message;
    if (msg.includes("not found") || msg.includes("404")) {
      return { success: false, error: `Repository not found: ${parsed.owner}/${parsed.repo}` };
    }
    if (msg.includes("timeout")) {
      return { success: false, error: `Clone timed out after ${CLONE_TIMEOUT / 1000}s` };
    }
    return { success: false, error: `Clone failed: ${msg}` };
  }
}
