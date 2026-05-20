"use client";

import { useEffect, useState, useRef, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { streamScan, type ScanEvent, type ScanReport } from "@/lib/api";
import { addScanToHistory } from "@/lib/storage";

interface LogEntry {
  phase: string;
  message: string;
  progress: number;
}

function ScanContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const scanId = searchParams.get("id") || "";
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("Connecting...");
  const [message, setMessage] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scanId) return;
    const cleanup = streamScan(
      scanId,
      (event: ScanEvent) => {
        if (event.type === "progress") {
          setProgress(event.progress || 0);
          setPhase(event.phase || "");
          setMessage(event.message || "");
          setLogs(prev => [...prev, {
            phase: event.phase || "",
            message: event.message || "",
            progress: event.progress || 0,
          }]);
        }
        if (event.type === "error") setError(event.message || "Scan failed");
        if (event.type === "report") {
          const report = event.data as unknown as ScanReport;
          if (report) {
            const criticals = report.findings?.filter(f => f.severity === "critical").length || 0;
            const highs = report.findings?.filter(f => f.severity === "high").length || 0;
            addScanToHistory({
              scan_id: scanId,
              target_url: report.target_url,
              repo_url: report.repo_url,
              scan_mode: report.scan_mode,
              started_at: new Date().toISOString(),
              grade: report.owner_summary?.grade || null,
              finding_count: report.findings?.length || 0,
              critical_count: criticals,
              high_count: highs,
            });
          }
        }
      },
      () => setDone(true)
    );
    return cleanup;
  }, [scanId]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (!scanId) {
    return <div className="max-w-3xl mx-auto px-6 py-12 text-text-muted">No scan ID provided.</div>;
  }

  const phaseLabel = phase.replace(/_/g, " ").replace(/DeepScanPhase\./, "");

  return (
    <div className="max-w-3xl mx-auto px-6 py-12">
      <h1 className="text-2xl font-bold text-white mb-2">Scanning...</h1>
      <p className="text-text-muted text-sm mb-8 font-mono">Scan ID: {scanId}</p>

      <div className="mb-6">
        <div className="flex justify-between text-sm text-text-muted mb-2">
          <span className="capitalize">{phaseLabel}</span>
          <span className="font-mono">{Math.round(progress)}%</span>
        </div>
        <div className="w-full bg-bg-card rounded-full h-3 border border-border overflow-hidden">
          <div className="progress-fill h-full rounded-full" style={{ width: `${Math.min(progress, 100)}%` }} />
        </div>
        {message && <p className="text-xs text-text-muted mt-2">{message}</p>}
      </div>

      {error && <div className="glass-card p-4 text-critical text-sm mb-6" style={{ borderColor: "rgba(220, 38, 38, 0.3)" }}>{error}</div>}

      <div className="glass-card overflow-hidden">
        <div className="px-4 py-2.5 border-b border-border text-xs text-text-muted font-semibold uppercase tracking-wider">Scanner Log</div>
        <div className="max-h-96 overflow-y-auto p-4 space-y-1 text-xs font-mono">
          {logs.map((log, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-text-muted/50 shrink-0 w-12 text-right">{Math.round(log.progress)}%</span>
              <span className="text-primary shrink-0">{log.phase.replace(/DeepScanPhase\./, "")}</span>
              <span className="text-text-muted">{log.message}</span>
            </div>
          ))}
          {logs.length === 0 && <span className="text-text-muted">Waiting for events...</span>}
          <div ref={logEndRef} />
        </div>
      </div>

      {done && (
        <div className="mt-6 text-center">
          <button onClick={() => router.push(`/report/?id=${scanId}`)} className="btn-primary">
            View Report
          </button>
        </div>
      )}
    </div>
  );
}

export default function ScanProgress() {
  return (
    <Suspense fallback={<div className="max-w-3xl mx-auto px-6 py-12 text-text-muted">Loading...</div>}>
      <ScanContent />
    </Suspense>
  );
}
