/**
 * Upload Validator — 4-layer self-protection for file uploads
 *
 * Layer 1: Client-side quick reject (extension, size, MIME)
 * Layer 2: Zip safety (bomb detection, path traversal, symlinks) — uses yauzl
 * Layer 3: Content safety (polyglot, encoding, per-file size)
 * Layer 4: Process isolation (handled by upload-session.ts)
 */

import * as yauzl from "yauzl";
import * as fs from "fs";
import * as path from "path";

// ---- Layer 1: Client-side constants ----

export const ACCEPTED_EXTENSIONS = new Set([".md", ".zip", ".json", ".yaml", ".yml"]);

export const BLOCKED_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".app", ".dmg",
  ".sh", ".bat", ".cmd", ".ps1",
]);

export const BLOCKED_MIMES = new Set([
  "application/x-executable",
  "application/x-mach-binary",
  "application/x-dosexec",
  "application/x-msdownload",
]);

export const MAX_SIZES: Record<string, number> = {
  ".md": 1024 * 1024,
  ".zip": 10 * 1024 * 1024,
  ".json": 1024 * 1024,
  ".yaml": 512 * 1024,
  ".yml": 512 * 1024,
};

export const ZIP_MAX_DECOMPRESSED = 50 * 1024 * 1024;
export const ZIP_MAX_RATIO = 100;
export const ZIP_MAX_ENTRIES = 500;
export const ZIP_PER_FILE_MAX = 1024 * 1024;

export function isAcceptedExtension(ext: string): boolean {
  const lower = ext.toLowerCase();
  if (BLOCKED_EXTENSIONS.has(lower)) return false;
  return ACCEPTED_EXTENSIONS.has(lower);
}

export function getMaxSize(ext: string): number {
  return MAX_SIZES[ext.toLowerCase()] ?? 0;
}

// ---- Layer 3: Content safety ----

/** Known binary file magic bytes */
const BINARY_MAGIC: { name: string; bytes: number[] }[] = [
  { name: "ELF",    bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "MZ/PE",  bytes: [0x4d, 0x5a] },
  { name: "Mach-O", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { name: "Mach-O", bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { name: "Mach-O", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { name: "Java",   bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { name: "Wasm",   bytes: [0x00, 0x61, 0x73, 0x6d] },
];

const PDF_MAGIC = Buffer.from("%PDF");

export function isBinaryContent(buf: Buffer): boolean {
  if (buf.length < 2) return false;

  for (const magic of BINARY_MAGIC) {
    if (buf.length >= magic.bytes.length) {
      let match = true;
      for (let i = 0; i < magic.bytes.length; i++) {
        if (buf[i] !== magic.bytes[i]) { match = false; break; }
      }
      if (match) return true;
    }
  }

  if (buf.length >= 4 && buf.subarray(0, 4).equals(PDF_MAGIC)) return true;

  return false;
}

export function isValidUtf8(buf: Buffer): boolean {
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(buf);
    const nullCount = buf.filter(b => b === 0).length;
    if (nullCount > buf.length * 0.1) return false;
    return decoded.length > 0;
  } catch {
    return false;
  }
}

// ---- Single file validation (Layer 3 content detection) ----

export interface SingleFileValidationResult {
  success: boolean;
  format: "skill_md" | "tool_json" | "config_yaml" | "unknown";
  filename: string;
  size: number;
  checks: {
    binaryContent: "pass" | "fail";
    encoding: "pass" | "fail";
    skillContent: "pass" | "fail";
    mimeType: "pass" | "fail";
  };
  error?: string;
}

const AGENT_KEYWORDS = [
  "agent", "skill", "mcp", "tool", "claude", "llm", "prompt",
  "assistant", "workflow", "automation", "instruction",
];

function isSkillMarkdown(text: string): boolean {
  // Check for YAML frontmatter with name and description
  if (/^---\s*\n/.test(text)) {
    const frontmatterEnd = text.indexOf("\n---", 4);
    if (frontmatterEnd !== -1) {
      const frontmatter = text.slice(0, frontmatterEnd);
      if (/\bname\s*:/i.test(frontmatter) && /\bdescription\s*:/i.test(frontmatter)) {
        return true;
      }
    }
  }

  // Check for instructional headers (## Steps, ## Instructions, ## Usage, etc.)
  if (/^#{1,3}\s+(Steps|Instructions|Usage|How to|Task|Goal|Overview|Description)\b/im.test(text)) {
    return true;
  }

  // Check for 2+ agent keywords
  let keywordCount = 0;
  const lower = text.toLowerCase();
  for (const kw of AGENT_KEYWORDS) {
    if (lower.includes(kw)) {
      keywordCount++;
      if (keywordCount >= 2) return true;
    }
  }

  return false;
}

function isToolOrMcpJson(text: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return false;
  const obj = parsed as Record<string, unknown>;

  // Check for mcpServers key
  if ("mcpServers" in obj) return true;

  // Check for tools array with proper tool definitions
  if (Array.isArray(obj["tools"])) {
    const tools = obj["tools"] as unknown[];
    if (tools.length > 0) {
      const first = tools[0];
      if (
        typeof first === "object" &&
        first !== null &&
        "name" in (first as Record<string, unknown>) &&
        "description" in (first as Record<string, unknown>) &&
        ("inputSchema" in (first as Record<string, unknown>) || "parameters" in (first as Record<string, unknown>))
      ) {
        return true;
      }
    }
  }

  // Reject generic package.json-style objects (has name, version, description but no tool fields)
  if ("name" in obj && "version" in obj && "description" in obj) {
    // This looks like package.json
    return false;
  }

  return false;
}

function isMcpYaml(text: string): boolean {
  // Check for mcpServers, tools, or servers top-level keys
  return /^(mcpServers|tools|servers)\s*:/m.test(text);
}

export function validateSingleFile(
  buf: Buffer,
  filename: string,
  mimeType?: string,
): SingleFileValidationResult {
  const ext = filename.includes(".") ? filename.slice(filename.lastIndexOf(".")).toLowerCase() : "";
  const base: Omit<SingleFileValidationResult, "checks"> = {
    success: false,
    format: "unknown",
    filename,
    size: buf.length,
  };
  const checks: SingleFileValidationResult["checks"] = {
    binaryContent: "pass",
    encoding: "pass",
    skillContent: "fail",
    mimeType: "pass",
  };

  // MIME type check
  if (mimeType && BLOCKED_MIMES.has(mimeType)) {
    checks.mimeType = "fail";
    return { ...base, checks, error: `MIME type blocked: ${mimeType}` };
  }

  // Binary content check
  if (isBinaryContent(buf)) {
    checks.binaryContent = "fail";
    return { ...base, checks, error: "Binary content detected" };
  }

  // UTF-8 encoding check
  if (!isValidUtf8(buf)) {
    checks.encoding = "fail";
    return { ...base, checks, error: "Invalid UTF-8 encoding" };
  }

  const text = buf.toString("utf-8");

  // Format-specific content detection
  let format: SingleFileValidationResult["format"] = "unknown";

  if (ext === ".md") {
    if (isSkillMarkdown(text)) {
      checks.skillContent = "pass";
      format = "skill_md";
    }
  } else if (ext === ".json") {
    if (isToolOrMcpJson(text)) {
      checks.skillContent = "pass";
      format = "tool_json";
    }
  } else if (ext === ".yaml" || ext === ".yml") {
    if (isMcpYaml(text)) {
      checks.skillContent = "pass";
      format = "config_yaml";
    }
  }

  const success = checks.mimeType === "pass"
    && checks.binaryContent === "pass"
    && checks.encoding === "pass"
    && checks.skillContent === "pass";

  if (!success && !checks) {
    return { ...base, format, checks, error: "File does not appear to be a valid skill/tool/config" };
  }

  return {
    ...base,
    success,
    format,
    checks,
    ...(!success ? { error: "File does not appear to be a valid skill/tool/config" } : {}),
  };
}

// ---- Layer 2: Zip safety ----

export interface ZipValidationResult {
  success: boolean;
  format: "zip_plugin" | "unknown";
  filename: string;
  compressedSize: number;
  decompressedSize: number;
  extractedFiles: number;
  fileTree: { path: string; label: string; isDir?: boolean }[];
  checks: {
    zipBomb: "pass" | "fail";
    pathTraversal: "pass" | "fail";
    binaryContent: "pass" | "fail";
    skillContent: "pass" | "fail";
  };
  error?: string;
}

const SKILL_MARKERS = [
  "skills/", ".claude-plugin/", "SKILL.md", "skill.md",
  ".mcp.json", "mcp.json", "settings.json", "plugin.json",
];

/** Promisified yauzl.fromBuffer */
function openZipFromBuffer(buf: Buffer): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buf, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) reject(err ?? new Error("Failed to open zip"));
      else resolve(zipfile);
    });
  });
}

/** Collect all entries from a yauzl ZipFile (lazy mode) */
function readAllEntries(zipfile: yauzl.ZipFile): Promise<yauzl.Entry[]> {
  return new Promise((resolve, reject) => {
    const entries: yauzl.Entry[] = [];
    zipfile.on("entry", (entry: yauzl.Entry) => {
      entries.push(entry);
      zipfile.readEntry();
    });
    zipfile.on("end", () => resolve(entries));
    zipfile.on("error", reject);
    zipfile.readEntry();
  });
}

/** Extract a single zip entry to a destination path on disk */
function extractEntry(zipfile: yauzl.ZipFile, entry: yauzl.Entry, destPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error("No read stream"));
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      const out = fs.createWriteStream(destPath);
      stream.on("error", reject);
      out.on("error", reject);
      out.on("close", resolve);
      stream.pipe(out);
    });
  });
}

/** Walk a directory recursively, returning relative file paths */
function walkDir(dir: string, base: string = dir): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(full, base));
    } else {
      results.push(path.relative(base, full));
    }
  }
  return results;
}

/** Build a display file tree, collapsing the skills/ directory prefix */
function buildFileTree(files: string[]): { path: string; label: string; isDir?: boolean }[] {
  const tree: { path: string; label: string; isDir?: boolean }[] = [];
  const dirs = new Set<string>();

  for (const f of files) {
    // Collect parent dirs
    const parts = f.split(path.sep);
    for (let i = 1; i < parts.length; i++) {
      dirs.add(parts.slice(0, i).join(path.sep));
    }
  }

  // Add directory entries first
  for (const d of Array.from(dirs).sort()) {
    const label = d.startsWith("skills/") || d.startsWith("skills" + path.sep)
      ? d
      : d;
    tree.push({ path: d, label, isDir: true });
  }

  // Add file entries
  for (const f of files.sort()) {
    tree.push({ path: f, label: f });
  }

  return tree;
}

export async function validateZipBuffer(
  buf: Buffer,
  filename: string,
  sessionDir: string,
): Promise<ZipValidationResult> {
  const checks: ZipValidationResult["checks"] = {
    zipBomb: "pass",
    pathTraversal: "pass",
    binaryContent: "pass",
    skillContent: "fail",
  };

  const base: Omit<ZipValidationResult, "checks"> = {
    success: false,
    format: "unknown",
    filename,
    compressedSize: buf.length,
    decompressedSize: 0,
    extractedFiles: 0,
    fileTree: [],
  };

  let zipfile: yauzl.ZipFile;
  try {
    zipfile = await openZipFromBuffer(buf);
  } catch (err) {
    return { ...base, checks, error: `Failed to open zip: ${err}` };
  }

  let entries: yauzl.Entry[];
  try {
    entries = await readAllEntries(zipfile);
  } catch (err) {
    return { ...base, checks, error: `Failed to read zip entries: ${err}` };
  }

  // Check entry count
  if (entries.length > ZIP_MAX_ENTRIES) {
    checks.zipBomb = "fail";
    return {
      ...base,
      checks,
      error: `Too many entries: ${entries.length} > ${ZIP_MAX_ENTRIES}`,
    };
  }

  // Compute total decompressed size and check for bombs
  let totalDecompressed = 0;
  for (const entry of entries) {
    totalDecompressed += entry.uncompressedSize;
  }

  base.decompressedSize = totalDecompressed;

  if (totalDecompressed > ZIP_MAX_DECOMPRESSED) {
    checks.zipBomb = "fail";
    return { ...base, checks, error: `Decompressed size too large: ${totalDecompressed}` };
  }

  const ratio = buf.length > 0 ? totalDecompressed / buf.length : 0;
  if (ratio > ZIP_MAX_RATIO) {
    checks.zipBomb = "fail";
    return { ...base, checks, error: `Compression ratio too high: ${ratio.toFixed(1)}x` };
  }

  // Path traversal and symlink checks
  for (const entry of entries) {
    const entryName: string = (entry as unknown as { fileName: string }).fileName;
    if (entryName.includes("..") || entryName.startsWith("/")) {
      checks.pathTraversal = "fail";
      return { ...base, checks, error: `Path traversal detected: ${entryName}` };
    }
    // Check for symlinks via unix mode bits (0xA000 = symlink)
    const externalAttr = (entry as unknown as { externalFileAttributes: number }).externalFileAttributes;
    const unixMode = (externalAttr >> 16) & 0xFFFF;
    const isSymlink = (unixMode & 0xF000) === 0xA000;
    if (isSymlink) {
      checks.pathTraversal = "fail";
      return { ...base, checks, error: `Symlink detected: ${entryName}` };
    }
  }

  // Extract files to sessionDir
  const extractedPaths: string[] = [];
  // Re-open buffer for extraction (entry streams require the original zipfile handle)
  let extractZip: yauzl.ZipFile;
  try {
    extractZip = await openZipFromBuffer(buf);
  } catch (err) {
    return { ...base, checks, error: `Failed to open zip for extraction: ${err}` };
  }

  const extractEntries = await readAllEntries(extractZip);

  for (const entry of extractEntries) {
    const entryName: string = (entry as unknown as { fileName: string }).fileName;
    // Skip directory entries
    if (entryName.endsWith("/")) continue;
    // Skip entries larger than ZIP_PER_FILE_MAX
    if (entry.uncompressedSize > ZIP_PER_FILE_MAX) {
      // Still continue but mark binaryContent fail? Just skip oversized files
      continue;
    }
    const destPath = path.join(sessionDir, entryName);
    try {
      await extractEntry(extractZip, entry, destPath);
      extractedPaths.push(entryName);
    } catch {
      // Skip files that fail to extract
    }
  }

  base.extractedFiles = extractedPaths.length;

  // Walk extracted files to build file tree
  const walkedFiles = walkDir(sessionDir);
  base.fileTree = buildFileTree(walkedFiles);

  // Check skill markers
  const allPaths = extractedPaths.join("\n");
  const hasSkillContent = SKILL_MARKERS.some(marker =>
    extractedPaths.some(p => p.includes(marker) || path.basename(p) === marker)
  );

  if (hasSkillContent) {
    checks.skillContent = "pass";
  }

  // Check binary content in extracted files
  for (const relPath of extractedPaths) {
    const fullPath = path.join(sessionDir, relPath);
    try {
      const content = fs.readFileSync(fullPath);
      if (isBinaryContent(content)) {
        checks.binaryContent = "fail";
        break;
      }
    } catch {
      // Skip unreadable files
    }
  }

  const success = checks.zipBomb === "pass"
    && checks.pathTraversal === "pass"
    && checks.skillContent === "pass";

  return {
    ...base,
    success,
    format: success ? "zip_plugin" : "unknown",
    checks,
  };
}
