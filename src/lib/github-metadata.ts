/**
 * GitHub Metadata Fetcher — retrieves repo and author signals from GitHub REST API.
 * Tier 1 (quick, <1s): author profile, repo vitals, license.
 * Tier 3 (deep, opt-in): contributors, star velocity.
 *
 * Uses native fetch. Requires GITHUB_TOKEN env var for higher rate limits (optional).
 * Without a token: 60 requests/hour. With token: 5000 requests/hour.
 */

import type { MetadataSignals } from "@/engine/types";

const GITHUB_API = "https://api.github.com";
const REQUEST_TIMEOUT = 5000;

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "AgentCanary/0.2.0",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

async function githubFetch(path: string): Promise<unknown | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    const res = await fetch(`${GITHUB_API}${path}`, {
      headers: getHeaders(),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  const now = Date.now();
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}

export async function fetchQuickMetadata(
  owner: string,
  repo: string,
): Promise<Pick<MetadataSignals, "author" | "repo">> {
  const [userData, repoData] = await Promise.all([
    githubFetch(`/users/${owner}`),
    githubFetch(`/repos/${owner}/${repo}`),
  ]);

  let author: MetadataSignals["author"] = null;
  if (userData && typeof userData === "object") {
    const u = userData as Record<string, unknown>;
    author = {
      login: String(u.login || owner),
      type: u.type === "Organization" ? "Organization" : "User",
      accountAge: u.created_at ? daysSince(String(u.created_at)) : 0,
      publicRepos: Number(u.public_repos || 0),
      followers: Number(u.followers || 0),
      profileComplete: Boolean(u.bio || u.email || u.blog),
    };
  }

  let repoInfo: MetadataSignals["repo"] = null;
  if (repoData && typeof repoData === "object") {
    const r = repoData as Record<string, unknown>;
    const license = r.license as Record<string, unknown> | null;
    const repoAge = r.created_at ? daysSince(String(r.created_at)) : 0;

    repoInfo = {
      stars: Number(r.stargazers_count || 0),
      forks: Number(r.forks_count || 0),
      age: repoAge,
      lastPush: String(r.pushed_at || ""),
      openIssues: Number(r.open_issues_count || 0),
      license: license ? (license.spdx_id || license.key || null) as string | null : null,
    };
  }

  return { author, repo: repoInfo };
}

export async function fetchDeepMetadata(
  owner: string,
  repo: string,
  existingRepo: MetadataSignals["repo"],
): Promise<Partial<Pick<NonNullable<MetadataSignals["repo"]>, "contributorCount" | "topContributorPct" | "starsPerDay">>> {
  const result: {
    contributorCount?: number;
    topContributorPct?: number;
    starsPerDay?: number;
  } = {};

  const contributors = await githubFetch(`/repos/${owner}/${repo}/contributors?per_page=100`);
  if (Array.isArray(contributors) && contributors.length > 0) {
    result.contributorCount = contributors.length;
    const totalContributions = contributors.reduce(
      (sum: number, c: Record<string, unknown>) => sum + Number(c.contributions || 0),
      0,
    );
    if (totalContributions > 0) {
      const topContributions = Number((contributors[0] as Record<string, unknown>).contributions || 0);
      result.topContributorPct = Math.round((topContributions / totalContributions) * 100);
    }
  }

  if (existingRepo && existingRepo.age > 0) {
    result.starsPerDay = Math.round((existingRepo.stars / existingRepo.age) * 100) / 100;
  }

  return result;
}
