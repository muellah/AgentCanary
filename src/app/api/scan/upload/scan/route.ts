/**
 * POST /api/scan/upload/scan
 * Body: { sessionId: "upload-..." }
 * Runs security scan on already-validated upload.
 * Returns OrchestratorResult merged with uploadValidation metadata.
 */

import { NextRequest, NextResponse } from "next/server";
import { getSession, cleanupSession, markScanning } from "@/lib/upload-session";
import { scanUploadedFile } from "@/lib/scan-orchestrator";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { sessionId } = body;

    if (!sessionId || typeof sessionId !== "string") {
      return NextResponse.json(
        { success: false, error: "Missing sessionId" },
        { status: 400 }
      );
    }

    // Validate session ID format (defense-in-depth)
    if (!/^upload-\d+-[a-f0-9]{8}$/.test(sessionId)) {
      return NextResponse.json(
        { success: false, error: "Invalid sessionId format" },
        { status: 400 }
      );
    }

    const session = getSession(sessionId);
    if (!session) {
      return NextResponse.json(
        { success: false, error: "Session not found or expired. Please re-upload." },
        { status: 404 }
      );
    }

    try {
      markScanning(sessionId);
      const result = await scanUploadedFile(session.dir, session.format);
      return NextResponse.json({ ...result, uploadValidation: session.validation });
    } finally {
      cleanupSession(sessionId);
    }
  } catch (err) {
    console.error("Upload scan error:", err);
    return NextResponse.json(
      { success: false, error: `Scan failed: ${(err as Error).message}` },
      { status: 500 }
    );
  }
}
