/**
 * POST /api/scan/upload/validate
 * Accepts: multipart/form-data with a single "file" field
 * Returns: validation result with session ID for subsequent scan
 */

import { NextRequest, NextResponse } from "next/server";
import { extname } from "path";
import { writeFile } from "fs/promises";
import { join } from "path";
import {
  isAcceptedExtension, getMaxSize,
  validateZipBuffer, validateSingleFile,
} from "@/lib/upload-validator";
import { createSession, cleanupSession } from "@/lib/upload-session";

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get("file");

    if (!file || !(file instanceof File)) {
      return NextResponse.json(
        { success: false, error: "No file uploaded. Send a 'file' field in multipart/form-data." },
        { status: 400 }
      );
    }

    const filename = file.name;
    const ext = extname(filename).toLowerCase();

    // Layer 1: Extension check
    if (!isAcceptedExtension(ext)) {
      return NextResponse.json({
        success: false,
        validation: { format: "unknown", checks: {} },
        error: `File type "${ext}" is not accepted. Supported: .md, .zip, .json, .yaml, .yml`,
      }, { status: 422 });
    }

    // Layer 1: Size check
    const maxSize = getMaxSize(ext);
    const buf = Buffer.from(await file.arrayBuffer());
    if (buf.length > maxSize) {
      return NextResponse.json({
        success: false,
        validation: { format: "unknown", checks: {} },
        error: `File too large (${(buf.length / 1024).toFixed(0)}KB). Max ${(maxSize / 1024).toFixed(0)}KB for ${ext} files.`,
      }, { status: 422 });
    }

    // Layer 2-3: Format-specific validation
    if (ext === ".zip") {
      // Create session FIRST, then validate zip into session dir
      const session = createSession(filename, "zip_plugin");

      const result = await validateZipBuffer(buf, filename, session.dir);
      if (!result.success) {
        cleanupSession(session.id);
        return NextResponse.json({
          success: false,
          validation: {
            format: result.format,
            filename, compressedSize: result.compressedSize,
            decompressedSize: result.decompressedSize,
            extractedFiles: result.extractedFiles,
            fileTree: result.fileTree,
            checks: result.checks,
          },
          error: result.error,
        }, { status: 422 });
      }

      session.format = result.format;
      session.validation = {
        format: result.format, filename,
        compressedSize: result.compressedSize,
        decompressedSize: result.decompressedSize,
        extractedFiles: result.extractedFiles,
        fileTree: result.fileTree,
        checks: result.checks,
      };

      return NextResponse.json({
        success: true,
        sessionId: session.id,
        validation: session.validation,
      });
    } else {
      // Single file: .md, .json, .yaml
      const result = validateSingleFile(buf, filename, file.type || undefined);
      if (!result.success) {
        return NextResponse.json({
          success: false,
          validation: {
            format: result.format, filename, size: result.size, checks: result.checks,
          },
          error: result.error,
        }, { status: 422 });
      }

      const session = createSession(filename, result.format);
      await writeFile(join(session.dir, filename), buf);

      session.validation = {
        format: result.format, filename, size: result.size, checks: result.checks,
      };

      return NextResponse.json({
        success: true,
        sessionId: session.id,
        validation: session.validation,
      });
    }
  } catch (err) {
    console.error("Upload validate error:", err);
    return NextResponse.json(
      { success: false, error: `Validation failed: ${(err as Error).message}` },
      { status: 500 }
    );
  }
}
