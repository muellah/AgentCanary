/**
 * POST /api/scan/file
 * Body: { content: "file contents...", filename: "SKILL.md", type?: "skill_file" }
 * Returns: OrchestratorResult
 */

import { NextRequest, NextResponse } from "next/server";
import { scanContent } from "@/lib/scan-orchestrator";
import type { TargetType } from "@/engine/types";

const MAX_CONTENT_SIZE = 1024 * 1024; // 1MB max

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { content, filename, type } = body;

    if (!content || typeof content !== "string") {
      return NextResponse.json(
        { success: false, error: "Missing or invalid 'content' parameter" },
        { status: 400 }
      );
    }

    if (content.length > MAX_CONTENT_SIZE) {
      return NextResponse.json(
        { success: false, error: `Content too large (${(content.length / 1024).toFixed(0)}KB). Max 1MB.` },
        { status: 400 }
      );
    }

    const fname = typeof filename === "string" ? filename : "untitled";
    const targetType = (typeof type === "string" ? type : undefined) as TargetType | undefined;

    const result = await scanContent(content, fname, targetType);

    return NextResponse.json(result, {
      status: result.success ? 200 : 500,
    });
  } catch (err) {
    console.error("File scan error:", err);
    return NextResponse.json(
      { success: false, error: `Scan failed: ${(err as Error).message}` },
      { status: 500 }
    );
  }
}
