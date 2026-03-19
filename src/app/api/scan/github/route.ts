/**
 * POST /api/scan/github
 * Body: { url: "https://github.com/owner/repo" }
 * Returns: OrchestratorResult
 */

import { NextRequest, NextResponse } from "next/server";
import { scanGitHubRepo } from "@/lib/scan-orchestrator";
import { parseGitHubUrl } from "@/lib/github-fetcher";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json(
        { success: false, error: "Missing or invalid 'url' parameter" },
        { status: 400 }
      );
    }

    // Validate it looks like a GitHub URL
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return NextResponse.json(
        { success: false, error: "Invalid GitHub URL. Expected format: https://github.com/owner/repo" },
        { status: 400 }
      );
    }

    const result = await scanGitHubRepo(url);

    return NextResponse.json(result, {
      status: result.success ? 200 : 500,
    });
  } catch (err) {
    console.error("GitHub scan error:", err);
    return NextResponse.json(
      { success: false, error: `Scan failed: ${(err as Error).message}` },
      { status: 500 }
    );
  }
}
