/**
 * Upload Validator — 4-layer self-protection for file uploads
 *
 * Layer 1: Client-side quick reject (extension, size, MIME)
 * Layer 2: Zip safety (bomb detection, path traversal, symlinks) — uses yauzl
 * Layer 3: Content safety (polyglot, encoding, per-file size)
 * Layer 4: Process isolation (handled by upload-session.ts)
 */

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
