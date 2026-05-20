"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { getReport, type ScanReport } from "@/lib/api";
import { GradeBadge } from "@/components/GradeBadge";
import { FindingCard } from "@/components/FindingCard";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

function ReportContent() {
  const searchParams = useSearchParams();
  const scanId = searchParams.get("id") || "";
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [scannerFilter, setScannerFilter] = useState("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!scanId) return;
    getReport(scanId).then(setReport).catch(e => setError(e.message));
  }, [scanId]);

  if (!scanId) return <div className="max-w-4xl mx-auto px-6 py-12 text-text-muted">No scan ID.</div>;
  if (error) return <div className="max-w-4xl mx-auto px-6 py-12"><div className="p-4 rounded-lg bg-critical/10 border border-critical/30 text-critical">{error}</div></div>;
  if (!report) return <div className="max-w-4xl mx-auto px-6 py-12 text-text-muted">Loading report...</div>;

  const findings = report.findings || [];
  const criticals = findings.filter(f => f.severity === "critical").length;
  const highs = findings.filter(f => f.severity === "high").length;
  const mediums = findings.filter(f => f.severity === "medium").length;
  const lows = findings.filter(f => f.severity === "low").length;
  const scanners = [...new Set(findings.map(f => f.scanner_name))].sort();

  const filtered = findings.filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (scannerFilter !== "all" && f.scanner_name !== scannerFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return f.title.toLowerCase().includes(q) || f.description?.toLowerCase().includes(q) || f.scanner_name.toLowerCase().includes(q) || f.code_location?.file_path?.toLowerCase().includes(q) || f.endpoint_url?.toLowerCase().includes(q);
    }
    return true;
  });

  const grade = report.owner_summary?.grade || "?";

  return (
    <div className="max-w-5xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-start gap-6 mb-8">
        <GradeBadge grade={grade} />
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">Scan Report</h1>
          <p className="text-text-muted text-sm mt-1">
            {report.target_url && <span>{report.target_url} | </span>}
            {report.repo_url && <span>{report.repo_url} | </span>}
            {report.framework && <span>{report.framework} | </span>}
            {report.backend && <span>{report.backend} | </span>}
            {report.scan_duration_seconds}s | {report.scanners_run.length} scanners
          </p>
          {report.owner_summary?.risk_summary && (
            <p className="text-text-muted text-sm mt-3 leading-relaxed">{report.owner_summary.risk_summary}</p>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3 mb-8">
        {[
          { label: "Total", value: findings.length, color: "text-text" },
          { label: "Critical", value: criticals, color: "text-critical" },
          { label: "High", value: highs, color: "text-high" },
          { label: "Medium", value: mediums, color: "text-medium" },
          { label: "Low", value: lows, color: "text-low" },
        ].map(s => (
          <div key={s.label} className="glass-card p-4 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-text-muted mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Key Risks */}
      {report.owner_summary?.key_risks && report.owner_summary.key_risks.length > 0 && (
        <div className="glass-card p-5 mb-8">
          <h2 className="text-sm font-medium text-text-accent mb-3">Key Risks</h2>
          <ul className="space-y-2">
            {report.owner_summary.key_risks.map((risk, i) => (
              <li key={i} className="text-sm text-text-muted flex items-start gap-2">
                <span className="text-critical mt-0.5">!</span>{risk}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation */}
      {report.owner_summary?.remediation_phases && report.owner_summary.remediation_phases.length > 0 && (
        <div className="glass-card p-5 mb-8">
          <h2 className="text-sm font-medium text-text-accent mb-3">Remediation Plan</h2>
          <div className="space-y-3">
            {report.owner_summary.remediation_phases.map(phase => (
              <div key={phase.phase_number} className="flex gap-3">
                <div className="w-7 h-7 rounded-full bg-primary/20 text-primary text-xs font-bold flex items-center justify-center shrink-0">{phase.phase_number}</div>
                <div>
                  <div className="text-sm font-medium text-text">{phase.title}</div>
                  <div className="text-xs text-text-muted mt-0.5">{phase.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="mb-4">
        <div className="flex items-center gap-3 flex-wrap">
          <h2 className="text-lg font-bold text-text-accent">Findings ({filtered.length})</h2>
          <div className="flex gap-1.5 flex-wrap">
            {(["all", "critical", "high", "medium", "low", "info"] as SeverityFilter[]).map(s => (
              <button key={s} onClick={() => setSeverityFilter(s)} className={`px-2.5 py-1 rounded text-xs transition-colors ${severityFilter === s ? "bg-primary/20 text-text-accent border border-primary/40" : "bg-bg-card text-text-muted border border-border hover:border-border-hover"}`}>
                {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
          <select value={scannerFilter} onChange={e => setScannerFilter(e.target.value)} className="input-glass text-xs !py-1.5 !px-3">
            <option value="all">All scanners</option>
            {scanners.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input type="text" placeholder="Search findings..." value={search} onChange={e => setSearch(e.target.value)} className="bg-bg-input border border-border rounded-lg px-3 py-1.5 text-xs text-text placeholder:text-text-muted/40 focus:outline-none focus:border-border-hover flex-1 min-w-[200px]" />
        </div>
      </div>

      {/* Findings list */}
      <div className="space-y-2">
        {filtered.map((f, i) => <FindingCard key={f.id} finding={f} index={i + 1} />)}
        {filtered.length === 0 && <div className="text-center text-text-muted py-12">No findings match your filters.</div>}
      </div>

      {/* Export */}
      <div className="mt-8 flex justify-end">
        <button onClick={() => {
          const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `isitsecure-report-${scanId}.json`; a.click(); URL.revokeObjectURL(url);
        }} className="border border-border text-text-muted hover:text-text-accent hover:border-border-hover px-4 py-2 rounded-lg text-sm transition-colors">
          Export JSON
        </button>
      </div>
    </div>
  );
}

export default function Report() {
  return (
    <Suspense fallback={<div className="max-w-4xl mx-auto px-6 py-12 text-text-muted">Loading...</div>}>
      <ReportContent />
    </Suspense>
  );
}
