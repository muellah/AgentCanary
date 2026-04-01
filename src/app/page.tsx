"use client";

import { useState, useRef, useEffect } from "react";
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
  relevanceWarning?: string;
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
        setSessionId(null); // Session is cleaned up server-side after scan
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
            v0.2.0
          </span>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 px-6 py-8">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Mode Tabs */}
          <div className="flex gap-2">
            <button
              onClick={() => { setMode("github"); setScanResult(null); setError(null); }}
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
              onClick={() => { setMode("upload"); setScanResult(null); setError(null); }}
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

// ---- Summary generation ----

interface ScanSummary {
  riskLine: string;
  narrative: string;
  topConcerns: string[];
  positives: string[];
  bottomLine: string;
}

function generateSummary(data: ScanResponse): ScanSummary {
  const verdict = data.aggregateVerdict || "SAFE";
  const findings = data.results?.flatMap((r) => r.findings) || [];
  const score = data.aggregateScore ?? 100;

  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const medCount = findings.filter((f) => f.severity === "medium").length;

  // Risk line
  const riskLabels: Record<string, string> = {
    SAFE: "LOW RISK \u2014 No significant security issues detected",
    CAUTION: "MODERATE RISK \u2014 Some concerns found, review recommended",
    SUSPICIOUS: "HIGH RISK \u2014 Significant security concerns detected",
    DANGEROUS: "CRITICAL RISK \u2014 Not safe to use without major fixes",
  };
  const riskLine = riskLabels[verdict] || riskLabels.CAUTION;

  // Narrative
  const parts: string[] = [];
  if (data.shortCircuit) {
    parts.push("Confirmed malicious patterns were detected in this code. This is not a false positive \u2014 the code contains known attack techniques.");
  } else if (critCount > 0 || highCount > 0) {
    const issues: string[] = [];
    if (critCount > 0) issues.push(`${critCount} critical`);
    if (highCount > 0) issues.push(`${highCount} high-severity`);
    parts.push(`Found ${issues.join(" and ")} issue${critCount + highCount > 1 ? "s" : ""} that need attention before this code can be trusted.`);
  } else if (medCount > 0) {
    parts.push(`Found ${medCount} medium-severity issue${medCount > 1 ? "s" : ""}. No critical problems, but worth reviewing.`);
  } else {
    parts.push("No security issues were detected in the scanned code.");
  }
  const narrative = parts.join(" ");

  // Top concerns — deduplicate by reportTitle, take critical/high only
  const seen = new Set<string>();
  const topConcerns: string[] = [];
  for (const f of findings) {
    if (f.severity !== "critical" && f.severity !== "high") continue;
    if (seen.has(f.reportTitle)) continue;
    seen.add(f.reportTitle);
    topConcerns.push(f.reportTitle);
    if (topConcerns.length >= 5) break;
  }

  // Positives
  const positives: string[] = [];
  if (!data.shortCircuit) {
    if (score >= 80) positives.push("Code score is clean (no malicious patterns)");
    if (findings.every((f) => f.severity !== "critical")) positives.push("No critical-severity findings");
    const categories = new Set(findings.map((f) => f.category));
    if (!categories.has("data_exfiltration")) positives.push("No data exfiltration detected");
    if (!categories.has("credential_harvesting")) positives.push("No credential harvesting detected");
    if (data.filesScanned && data.filesScanned > 10 && findings.length < 3) positives.push("Large codebase with very few findings");
  }

  // Bottom line
  let bottomLine: string;
  if (data.shortCircuit) {
    bottomLine = "Do not install or run this code. It contains confirmed malicious behavior.";
  } else if (verdict === "DANGEROUS") {
    bottomLine = "This code has serious security issues. Do not use it in its current state without thorough review and fixes.";
  } else if (verdict === "SUSPICIOUS") {
    bottomLine = "Significant concerns were found. Proceed with caution and review the flagged issues carefully before using.";
  } else if (verdict === "CAUTION") {
    bottomLine = "Some issues were found but nothing critically dangerous. Review the findings and assess whether they matter for your use case.";
  } else {
    bottomLine = "No significant security issues found. As always, review code yourself before running it in sensitive environments.";
  }

  return { riskLine, narrative, topConcerns, positives, bottomLine };
}

/** Strip CVE codes and other internal references from recommendation text */
function sanitizeRecommendation(text: string): string {
  return text
    .replace(/CVE-\d{4}-\d+/g, "a known vulnerability")
    .replace(/\s+demonstrated how\b/g, " showed that")
    .replace(/\s{2,}/g, " ")
    .trim();
}

interface GroupedFinding {
  finding: Finding;
  count: number;
  extraLocations: { line?: number; snippet?: string }[];
}

function groupFindings(findings: Finding[]): GroupedFinding[] {
  const groups: GroupedFinding[] = [];
  const seen = new Map<string, number>(); // key -> index in groups

  for (const f of findings) {
    const key = `${f.ruleId}::${f.reportTitle}::${f.severity}`;
    const idx = seen.get(key);
    if (idx !== undefined) {
      groups[idx].count++;
      if (f.location?.snippet && groups[idx].extraLocations.length < 3) {
        groups[idx].extraLocations.push(f.location);
      }
    } else {
      seen.set(key, groups.length);
      groups.push({ finding: f, count: 1, extraLocations: [] });
    }
  }
  return groups;
}

function ScanSummaryBlock({ data }: { data: ScanResponse }) {
  const summary = generateSummary(data);
  const verdict = data.aggregateVerdict || "SAFE";
  const config = VERDICT_CONFIG[verdict];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
      {/* Risk line */}
      <div className={`font-semibold text-sm ${config.color}`}>
        {summary.riskLine}
      </div>

      {/* Narrative */}
      <p className="text-sm text-gray-300">{summary.narrative}</p>

      {/* Top concerns */}
      {summary.topConcerns.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Key concerns</div>
          <ul className="space-y-1">
            {summary.topConcerns.map((concern, i) => (
              <li key={i} className="text-sm text-gray-400 flex items-start gap-2">
                <span className="text-red-500 shrink-0 mt-0.5">{"\u{25CF}"}</span>
                {concern}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Positives */}
      {summary.positives.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Positive signals</div>
          <ul className="space-y-1">
            {summary.positives.map((pos, i) => (
              <li key={i} className="text-sm text-gray-400 flex items-start gap-2">
                <span className="text-emerald-500 shrink-0 mt-0.5">{"\u{25CF}"}</span>
                {pos}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Bottom line */}
      <div className="border-t border-gray-800 pt-3">
        <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Bottom line</div>
        <p className="text-sm text-gray-200">{summary.bottomLine}</p>
      </div>
    </div>
  );
}

function ScanResults({ data }: { data: ScanResponse }) {
  const verdict = data.aggregateVerdict || "SAFE";
  const config = VERDICT_CONFIG[verdict];
  const allFindings = data.results?.flatMap((r) => r.findings) || [];
  const groupedFindings = groupFindings(allFindings);
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [data]);

  return (
    <div ref={resultsRef} className="space-y-4 scroll-mt-4">
      {/* Relevance Warning */}
      {data.relevanceWarning && (
        <div className="bg-blue-950/40 border border-blue-800 rounded-lg p-4 flex items-start gap-3">
          <span className="text-lg shrink-0">{"\u{2139}\u{FE0F}"}</span>
          <p className="text-sm text-blue-300">{data.relevanceWarning}</p>
        </div>
      )}
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

      {/* Summary */}
      <ScanSummaryBlock data={data} />

      {/* Findings List */}
      {groupedFindings.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            Detailed Findings
          </h3>
          {groupedFindings.map(({ finding, count, extraLocations }, i) => (
            <div
              key={`${finding.ruleId}-${i}`}
              className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2 overflow-hidden"
            >
              <div className="flex items-start gap-2">
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded text-center shrink-0 mt-0.5 ${
                    SEVERITY_BADGE[finding.severity] || SEVERITY_BADGE.info
                  }`}
                >
                  {finding.severity.toUpperCase()}
                </span>
                <div className="font-medium text-gray-200 min-w-0">
                  {finding.reportTitle}
                  {count > 1 && (
                    <span className="ml-2 text-xs font-normal text-gray-500 bg-gray-800 rounded-full px-2 py-0.5">
                      {count}x
                    </span>
                  )}
                </div>
              </div>
              {finding.location?.snippet && (
                <pre className="text-xs bg-gray-950 border border-gray-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-gray-400">
                  {finding.location.line ? `Line ${finding.location.line}: ` : ""}
                  {finding.location.snippet}
                </pre>
              )}
              {extraLocations.length > 0 && (
                <div className="space-y-1">
                  {extraLocations.map((loc, j) => (
                    <pre key={j} className="text-xs bg-gray-950 border border-gray-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-gray-500">
                      {loc.line ? `Line ${loc.line}: ` : ""}{loc.snippet}
                    </pre>
                  ))}
                  {count > 1 + extraLocations.length && (
                    <div className="text-xs text-gray-600 pl-2">
                      +{count - 1 - extraLocations.length} more occurrence{count - 1 - extraLocations.length > 1 ? "s" : ""}
                    </div>
                  )}
                </div>
              )}
              {finding.recommendation && (
                <p className="text-xs text-gray-500">
                  {sanitizeRecommendation(finding.recommendation)}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* No Findings */}
      {groupedFindings.length === 0 && (
        <div className="text-center text-gray-500 py-4">
          No security issues detected. This doesn&apos;t guarantee safety — always review code manually.
        </div>
      )}
    </div>
  );
}
