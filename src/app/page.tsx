"use client";

import { useState, useRef } from "react";
// Client-side upload validation constants (subset of upload-validator.ts Layer 1)
const ACCEPTED_EXTENSIONS = new Set([".md", ".zip", ".json", ".yaml", ".yml"]);
const BLOCKED_EXTENSIONS = new Set([".exe", ".dll", ".so", ".dylib", ".app", ".dmg", ".sh", ".bat", ".cmd", ".ps1"]);
const BLOCKED_MIMES = new Set([
  "application/x-executable",
  "application/x-mach-binary",
  "application/x-dosexec",
  "application/x-msdownload",
]);
const MAX_SIZES: Record<string, number> = {
  ".md": 1024 * 1024,
  ".zip": 10 * 1024 * 1024,
  ".json": 1024 * 1024,
  ".yaml": 512 * 1024,
  ".yml": 512 * 1024,
};
function isAcceptedExtension(ext: string): boolean {
  const lower = ext.toLowerCase();
  if (BLOCKED_EXTENSIONS.has(lower)) return false;
  return ACCEPTED_EXTENSIONS.has(lower);
}
function getMaxSize(ext: string): number {
  return MAX_SIZES[ext.toLowerCase()] ?? 0;
}

type ScanMode = "github" | "upload";
type Verdict = "SAFE" | "CONDITIONAL_PASS" | "CAUTION" | "SUSPICIOUS" | "DANGEROUS";

interface Finding {
  ruleId: string;
  ruleTitle: string;
  severity: string;
  category: string;
  reportTitle: string;
  recommendation: string;
  location: { line?: number; snippet?: string } | null;
}

interface ScanResultData {
  findings: Finding[];
  verdict: Verdict;
  score: number;
  rulesChecked: number;
  target: { filename: string };
}

interface ScanResponse {
  success: boolean;
  results?: ScanResultData[];
  aggregateVerdict?: Verdict;
  aggregateScore?: number;
  totalFindings?: number;
  filesScanned?: number;
  rulesLoaded?: number;
  scanDuration?: number;
  shortCircuit?: boolean;
  verdictConfidence?: number;
  caveats?: { dimension: string; severity: string; text: string }[];
  error?: string;
}

interface ValidationResult {
  format: string;
  filename?: string;
  size?: number;
  compressedSize?: number;
  decompressedSize?: number;
  extractedFiles?: number;
  fileTree?: { path: string; label: string; isDir?: boolean }[];
  checks: Record<string, "pass" | "fail">;
}

const VERDICT_CONFIG: Record<Verdict, { emoji: string; color: string; bg: string; border: string }> = {
  SAFE: { emoji: "\u{1F7E2}", color: "text-emerald-400", bg: "bg-emerald-950/50", border: "border-emerald-800" },
  CONDITIONAL_PASS: { emoji: "\u{1F7E1}", color: "text-yellow-400", bg: "bg-yellow-950/50", border: "border-yellow-800" },
  CAUTION: { emoji: "\u{1F7E1}", color: "text-yellow-400", bg: "bg-yellow-950/50", border: "border-yellow-800" },
  SUSPICIOUS: { emoji: "\u{1F7E0}", color: "text-orange-400", bg: "bg-orange-950/50", border: "border-orange-800" },
  DANGEROUS: { emoji: "\u{1F534}", color: "text-red-400", bg: "bg-red-950/50", border: "border-red-800" },
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900 text-red-200",
  high: "bg-orange-900 text-orange-200",
  medium: "bg-yellow-900 text-yellow-200",
  low: "bg-blue-900 text-blue-200",
  info: "bg-gray-800 text-gray-300",
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getScanButtonLabel(format: string): string {
  if (format === "zip_plugin") return "Scan Plugin";
  if (format === "tool_json" || format === "config_yaml") return "Scan Config";
  return "Scan File";
}

interface FileInspectorProps {
  file: File;
  validationResult: ValidationResult;
  sessionId: string | null;
  inspectorError: string | null;
  inspectorErrorType: "validation" | "server" | null;
  scanning: boolean;
  onScan: () => void;
  onRetry: () => void;
}

function FileInspector({
  file,
  validationResult,
  sessionId,
  inspectorError,
  inspectorErrorType,
  scanning,
  onScan,
  onRetry,
}: FileInspectorProps) {
  const isZip = file.name.endsWith(".zip");
  const checks = validationResult.checks;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-4">
      {/* File info header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-medium text-gray-200 text-sm">{file.name}</div>
          {isZip && validationResult.compressedSize != null ? (
            <div className="text-xs text-gray-500 mt-0.5">
              {formatBytes(validationResult.compressedSize)} compressed
              {validationResult.decompressedSize != null && (
                <> &rarr; {formatBytes(validationResult.decompressedSize)} decompressed</>
              )}
              {validationResult.extractedFiles != null && (
                <> &middot; {validationResult.extractedFiles} file{validationResult.extractedFiles !== 1 ? "s" : ""}</>
              )}
            </div>
          ) : (
            <div className="text-xs text-gray-500 mt-0.5">{formatBytes(file.size)}</div>
          )}
        </div>
        <div className="text-xs text-gray-600 font-mono bg-gray-950 border border-gray-800 rounded px-2 py-1 shrink-0">
          {validationResult.format || "unknown"}
        </div>
      </div>

      {/* Validation badges */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(checks).map(([key, val]) => (
          <span
            key={key}
            className={`text-xs px-2 py-0.5 rounded border font-mono ${
              val === "pass"
                ? "bg-emerald-950/50 border-emerald-800 text-emerald-400"
                : "bg-red-950/50 border-red-800 text-red-400"
            }`}
          >
            {val === "pass" ? "✓" : "✗"} {key}
          </span>
        ))}
      </div>

      {/* File tree for zips */}
      {isZip && validationResult.fileTree && validationResult.fileTree.length > 0 && (
        <div className="bg-gray-950 border border-gray-800 rounded p-3 max-h-40 overflow-y-auto">
          <div className="text-xs text-gray-600 uppercase tracking-wider mb-2">Contents</div>
          <div className="space-y-0.5">
            {validationResult.fileTree.map((entry) => (
              <div key={entry.path} className="text-xs font-mono text-gray-400">
                {entry.isDir ? (
                  <span className="text-gray-600">{entry.label}/</span>
                ) : (
                  <span className="text-gray-300">{entry.label}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error states */}
      {inspectorError && inspectorErrorType === "validation" && (
        <div className="bg-red-950/50 border border-red-800 rounded p-3 text-red-300 text-sm">
          {inspectorError}
        </div>
      )}
      {inspectorError && inspectorErrorType === "server" && (
        <div className="bg-orange-950/50 border border-orange-800 rounded p-3 space-y-2">
          <div className="text-orange-300 text-sm">{inspectorError}</div>
          <button
            onClick={onRetry}
            className="text-xs text-orange-400 hover:text-orange-300 border border-orange-800 rounded px-2 py-1"
          >
            Try again
          </button>
        </div>
      )}

      {/* Scan button — only show if we have a valid session */}
      {sessionId && !inspectorError && (
        <button
          onClick={onScan}
          disabled={scanning}
          className={`w-full py-3 rounded-lg font-semibold transition-all ${
            scanning
              ? "bg-gray-800 text-gray-500 cursor-wait"
              : "bg-amber-600 hover:bg-amber-500 text-gray-950 cursor-pointer"
          }`}
        >
          {scanning ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning...
            </span>
          ) : (
            getScanButtonLabel(validationResult.format)
          )}
        </button>
      )}
    </div>
  );
}

export default function HomePage() {
  const [mode, setMode] = useState<ScanMode>("github");
  const [githubUrl, setGithubUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deepScan, setDeepScan] = useState(false);

  // Upload tab state
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const [inspectorError, setInspectorError] = useState<string | null>(null);
  const [inspectorErrorType, setInspectorErrorType] = useState<"validation" | "server" | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // GitHub scan
  async function handleGithubScan() {
    setScanning(true);
    setError(null);
    setScanResult(null);

    try {
      if (!githubUrl.trim()) {
        setError("Please enter a GitHub repository URL");
        setScanning(false);
        return;
      }
      const response = await fetch("/api/scan/github", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: githubUrl.trim() }),
      });
      const data: ScanResponse = await response.json();
      if (!data.success) {
        setError(data.error || "Scan failed");
      } else {
        setScanResult(data);
      }
    } catch (err) {
      setError(`Network error: ${(err as Error).message}`);
    } finally {
      setScanning(false);
    }
  }

  function handleFileSelected(file: File) {
    setUploadError(null);
    setScanResult(null);
    setValidationResult(null);
    setSessionId(null);
    setInspectorError(null);
    setInspectorErrorType(null);

    const lastDot = file.name.lastIndexOf(".");
    const ext = lastDot !== -1 ? file.name.slice(lastDot) : "";

    // Client-side Layer 1 checks
    if (!isAcceptedExtension(ext)) {
      setUploadError(`File type "${ext || "(none)"}" is not accepted. Supported: .md, .zip, .json, .yaml, .yml`);
      return;
    }

    const maxSize = getMaxSize(ext);
    if (maxSize > 0 && file.size > maxSize) {
      setUploadError(`File too large (${formatBytes(file.size)}). Max ${formatBytes(maxSize)} for ${ext} files.`);
      return;
    }

    if (file.type && BLOCKED_MIMES.has(file.type)) {
      setUploadError(`MIME type "${file.type}" is blocked.`);
      return;
    }

    setUploadFile(file);
    validateFile(file);
  }

  async function validateFile(file: File) {
    setValidating(true);
    setInspectorError(null);
    setInspectorErrorType(null);
    setSessionId(null);
    setValidationResult(null);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch("/api/scan/upload/validate", {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 422) {
          // Validation rejection — show inspector with error
          setValidationResult(data.validation || { format: "unknown", checks: {} });
          setInspectorError(data.error || "File did not pass validation");
          setInspectorErrorType("validation");
        } else {
          // Server error — show with retry
          setValidationResult(data.validation || { format: "unknown", checks: {} });
          setInspectorError(data.error || "Server error during validation");
          setInspectorErrorType("server");
        }
      } else {
        // Success — show inspector with scan button
        setValidationResult(data.validation);
        setSessionId(data.sessionId);
      }
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        setUploadError("Validation timed out. Please try again.");
      } else {
        setUploadError(`Network error: ${(err as Error).message}`);
      }
    } finally {
      clearTimeout(timeout);
      setValidating(false);
    }
  }

  async function handleUploadScan() {
    if (!sessionId) return;

    setScanning(true);
    setScanResult(null);
    setInspectorError(null);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch("/api/scan/upload/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId }),
        signal: controller.signal,
      });

      const data: ScanResponse = await response.json();

      if (!response.ok || !data.success) {
        setInspectorError(data.error || "Scan failed");
        setInspectorErrorType("server");
      } else {
        setScanResult(data);
      }
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        setInspectorError("Scan timed out. Please try again.");
        setInspectorErrorType("server");
      } else {
        setInspectorError(`Network error: ${(err as Error).message}`);
        setInspectorErrorType("server");
      }
    } finally {
      clearTimeout(timeout);
      setScanning(false);
    }
  }

  function handleRetry() {
    if (uploadFile) {
      validateFile(uploadFile);
    }
  }

  // Drag-and-drop handlers
  function handleDragOver(e: React.DragEvent) {
    e.preventDefault();
    setDragActive(true);
  }

  function handleDragLeave(e: React.DragEvent) {
    e.preventDefault();
    setDragActive(false);
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragActive(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 1) {
      setUploadError("Please upload one file at a time.");
      return;
    }
    if (files.length === 1) {
      handleFileSelected(files[0]);
    }
  }

  // Sample bar
  async function loadSample(filename: string) {
    setUploadError(null);
    setScanResult(null);
    try {
      const response = await fetch(`/samples/${filename}`);
      if (!response.ok) throw new Error(`Could not fetch sample: ${response.status}`);
      const blob = await response.blob();
      const file = new File([blob], filename, { type: blob.type });
      setUploadFile(file);
      setMode("upload");
      handleFileSelected(file);
    } catch (err) {
      setUploadError(`Failed to load sample: ${(err as Error).message}`);
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-600 flex items-center justify-center text-xl">
              {"\u{1F426}"}
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-100">AgentCanary</h1>
              <p className="text-xs text-gray-500 uppercase tracking-wider">
                AI Agent Supply Chain Security
              </p>
            </div>
          </div>
          <span className="text-xs text-gray-600 border border-gray-800 rounded px-2 py-1">
            v0.1.0 MVP
          </span>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 px-6 py-8">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Mode Tabs */}
          <div className="flex gap-2">
            <button
              onClick={() => setMode("github")}
              className={`flex-1 py-3 rounded-lg font-medium transition-colors ${
                mode === "github"
                  ? "bg-amber-900/50 border border-amber-700 text-amber-300"
                  : "bg-gray-900 border border-gray-800 text-gray-400 hover:border-gray-700"
              }`}
            >
              <div>{"\u{26A1}"} GitHub Repo</div>
              <div className="text-xs font-normal opacity-60 mt-0.5">MCP Servers &amp; Skill Repos</div>
            </button>
            <button
              onClick={() => setMode("upload")}
              className={`flex-1 py-3 rounded-lg font-medium transition-colors ${
                mode === "upload"
                  ? "bg-amber-900/50 border border-amber-700 text-amber-300"
                  : "bg-gray-900 border border-gray-800 text-gray-400 hover:border-gray-700"
              }`}
            >
              <div>{"\u{1F4C1}"} Upload File</div>
              <div className="text-xs font-normal opacity-60 mt-0.5">Skills, Plugins &amp; Tool Definitions</div>
            </button>
          </div>

          {/* Input Area */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
            {mode === "github" ? (
              <div>
                <label className="block text-sm text-gray-400 mb-2">
                  GitHub Repository URL
                </label>
                <input
                  type="text"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/owner/mcp-server-name"
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-3 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-amber-600"
                  onKeyDown={(e) => e.key === "Enter" && handleGithubScan()}
                />
                <label className="flex items-center gap-2 mt-3 text-sm text-gray-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={deepScan}
                    onChange={(e) => setDeepScan(e.target.checked)}
                    className="rounded border-gray-600 bg-gray-800"
                  />
                  Deep scan (slower — checks CVEs + contributor patterns)
                </label>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Drop zone */}
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer ${
                    dragActive
                      ? "border-amber-600 bg-amber-950/20"
                      : "border-gray-700 hover:border-gray-600"
                  }`}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".md,.zip,.json,.yaml,.yml"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleFileSelected(file);
                      // Reset so same file can be re-selected
                      e.target.value = "";
                    }}
                  />
                  <div className="text-3xl mb-3">{dragActive ? "\u{1F4E5}" : "\u{1F4C4}"}</div>
                  <div className="text-gray-400 text-sm mb-1">
                    Drag &amp; drop a file here, or{" "}
                    <span className="text-amber-500 hover:text-amber-400">browse files</span>
                  </div>
                  <div className="text-gray-600 text-xs">
                    .md, .zip, .json, .yaml, .yml &middot; Max 10 MB (zip), 1 MB (others)
                  </div>
                </div>

                {/* Upload error */}
                {uploadError && (
                  <div className="bg-red-950/50 border border-red-800 rounded-lg p-3 text-red-300 text-sm">
                    {uploadError}
                  </div>
                )}

                {/* Validating indicator */}
                {validating && (
                  <div className="flex items-center gap-2 text-sm text-gray-400">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Validating file...
                  </div>
                )}

                {/* File inspector */}
                {uploadFile && validationResult && !validating && (
                  <FileInspector
                    file={uploadFile}
                    validationResult={validationResult}
                    sessionId={sessionId}
                    inspectorError={inspectorError}
                    inspectorErrorType={inspectorErrorType}
                    scanning={scanning}
                    onScan={handleUploadScan}
                    onRetry={handleRetry}
                  />
                )}

                {/* Sample bar */}
                <div className="border-t border-gray-800 pt-3">
                  <div className="text-xs text-gray-600 mb-2">Try a sample:</div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => loadSample("safe-example.md")}
                      className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300 transition-colors"
                    >
                      {"\u{1F7E2}"} Safe skill
                    </button>
                    <button
                      onClick={() => loadSample("malicious-example.md")}
                      className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300 transition-colors"
                    >
                      {"\u{1F534}"} Malicious skill
                    </button>
                    <button
                      onClick={() => loadSample("suspicious-plugin.zip")}
                      className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300 transition-colors"
                    >
                      {"\u{1F4E6}"} Plugin bundle
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Scan Button — only for GitHub mode */}
          {mode === "github" && (
            <button
              onClick={handleGithubScan}
              disabled={scanning}
              className={`w-full py-4 rounded-lg font-semibold text-lg transition-all ${
                scanning
                  ? "bg-gray-800 text-gray-500 cursor-wait"
                  : "bg-amber-600 hover:bg-amber-500 text-gray-950 cursor-pointer"
              }`}
            >
              {scanning ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle
                      className="opacity-25"
                      cx="12" cy="12" r="10"
                      stroke="currentColor" strokeWidth="4" fill="none"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                  Scanning...
                </span>
              ) : (
                "Scan Repository"
              )}
            </button>
          )}

          {/* Error (GitHub mode) */}
          {error && mode === "github" && (
            <div className="bg-red-950/50 border border-red-800 rounded-lg p-4 text-red-300">
              {error}
            </div>
          )}

          {/* Results */}
          {scanResult && scanResult.success && (
            <ScanResults data={scanResult} />
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 px-6 py-4 text-center">
        <p className="text-xs text-gray-600">
          AgentCanary MVP &middot; AI Agent Supply Chain Security &middot; Built by Tamas
        </p>
        <p className="text-xs text-gray-700 mt-1">
          Powered by Claude &middot; Static analysis + Heuristic + Semantic + Composite detection
        </p>
      </footer>
    </div>
  );
}

function ScanResults({ data }: { data: ScanResponse }) {
  const verdict = data.aggregateVerdict || "SAFE";
  const config = VERDICT_CONFIG[verdict];
  const allFindings = data.results?.flatMap((r) => r.findings) || [];

  return (
    <div className="space-y-4">
      {/* Verdict Banner */}
      <div className={`${config.bg} border ${config.border} rounded-lg p-6 text-center`}>
        <div className="text-4xl mb-2">{config.emoji}</div>
        <div className={`text-2xl font-bold ${config.color}`}>{verdict}</div>
        <div className="text-gray-400 mt-1">
          Score: {data.aggregateScore}/100 &middot;{" "}
          Confidence: {data.verdictConfidence ? `${Math.round(data.verdictConfidence * 100)}%` : "—"} &middot;{" "}
          {data.totalFindings} finding{data.totalFindings !== 1 ? "s" : ""} &middot;{" "}
          {data.filesScanned} file{data.filesScanned !== 1 ? "s" : ""} scanned &middot;{" "}
          {data.rulesLoaded} rules &middot;{" "}
          {((data.scanDuration || 0) / 1000).toFixed(1)}s
        </div>
        {data.shortCircuit && (
          <div className="text-red-400 text-sm mt-2 font-semibold">
            Confirmed malicious pattern detected — short-circuit verdict applied
          </div>
        )}
        {data.caveats && data.caveats.length > 0 && (
          <div className="mt-3 space-y-1">
            {data.caveats.map((caveat, i) => (
              <div key={i} className="text-sm text-left">
                <span className={
                  caveat.severity === "critical" ? "text-red-400" :
                  caveat.severity === "warning" ? "text-yellow-400" :
                  "text-gray-400"
                }>
                  {caveat.severity === "critical" ? "\u{1F6A8}" : "\u{26A0}\u{FE0F}"}{" "}
                  {caveat.text}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Findings List */}
      {allFindings.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            Findings
          </h3>
          {allFindings.map((finding, i) => (
            <div
              key={`${finding.ruleId}-${i}`}
              className="bg-gray-900 border border-gray-800 rounded-lg p-4"
            >
              <div className="flex items-start gap-3">
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded ${
                    SEVERITY_BADGE[finding.severity] || SEVERITY_BADGE.info
                  }`}
                >
                  {finding.severity.toUpperCase()}
                </span>
                <div className="flex-1">
                  <div className="font-medium text-gray-200">{finding.reportTitle}</div>
                  <div className="text-xs text-gray-500 mt-1">
                    {finding.ruleId} &middot; {finding.category}
                  </div>
                  {finding.location?.snippet && (
                    <pre className="mt-2 text-xs bg-gray-950 border border-gray-800 rounded p-2 overflow-x-auto text-gray-400">
                      {finding.location.line ? `Line ${finding.location.line}: ` : ""}
                      {finding.location.snippet}
                    </pre>
                  )}
                  {finding.recommendation && (
                    <p className="mt-2 text-xs text-gray-500">
                      {finding.recommendation.substring(0, 200)}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* No Findings */}
      {allFindings.length === 0 && (
        <div className="text-center text-gray-500 py-4">
          No security issues detected. This doesn&apos;t guarantee safety — always review code manually.
        </div>
      )}
    </div>
  );
}
