"use client";

import { useState, type MouseEvent } from "react";
import { generateFix, type Finding, type FixResult } from "@/lib/api";
import { SeverityBadge } from "./SeverityBadge";

export function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const [fixLoading, setFixLoading] = useState(false);
  const [fix, setFix] = useState<FixResult | null>(null);
  const [fixError, setFixError] = useState("");

  const handleFix = async (e: MouseEvent) => {
    e.stopPropagation();
    if (fixLoading) return;
    setFixError("");
    setFixLoading(true);
    try {
      const snippet = finding.code_location?.code_snippet || "";
      const result = await generateFix(finding.id, snippet);
      setFix(result);
      if (!result.success && result.error) setFixError(result.error);
    } catch (err) {
      setFixError(err instanceof Error ? err.message : "Fix generation failed");
    } finally {
      setFixLoading(false);
    }
  };

  return (
    <div
      className="glass-card cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="p-4 flex items-start gap-3">
        <span className="text-text-muted text-sm mt-0.5 w-6 text-right shrink-0 font-mono">
          {index}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-text-muted font-mono">{finding.scanner_name}</span>
            <span className="text-xs text-text-muted/30">|</span>
            <span className="text-xs text-text-muted">{finding.source}</span>
          </div>
          <h3 className="text-sm font-medium text-white">{finding.title}</h3>
          {finding.code_location && (
            <p className="text-xs text-text-muted mt-1 font-mono">
              {finding.code_location.file_path}
              {finding.code_location.line_number ? `:${finding.code_location.line_number}` : ""}
            </p>
          )}
          {finding.endpoint_url && (
            <p className="text-xs text-text-muted mt-1 font-mono">
              {finding.http_method} {finding.endpoint_url}
            </p>
          )}
        </div>
        <span className="text-text-muted text-sm shrink-0 transition-transform" style={{ transform: expanded ? "rotate(45deg)" : "none" }}>+</span>
      </div>

      {expanded && (
        <div className="border-t border-border px-4 pb-4 pt-3 space-y-4 text-sm">
          {finding.description && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">Description</h4>
              <p className="text-text-muted whitespace-pre-wrap leading-relaxed">{finding.description}</p>
            </div>
          )}
          {finding.technical_detail && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">Technical Detail</h4>
              <p className="text-text-muted whitespace-pre-wrap leading-relaxed">{finding.technical_detail}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">Evidence</h4>
              <pre className="bg-bg-secondary border border-border rounded-xl p-3 text-xs overflow-x-auto font-mono text-text-muted">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation_guidance && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">Remediation</h4>
              <p className="text-text-muted whitespace-pre-wrap leading-relaxed">{finding.remediation_guidance}</p>
            </div>
          )}
          {finding.code_location?.code_snippet && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">Code</h4>
              <pre className="bg-bg-secondary border border-border rounded-xl p-3 text-xs overflow-x-auto font-mono text-text-muted">
                {finding.code_location.code_snippet}
              </pre>
            </div>
          )}
          {finding.code_location?.code_snippet && (
            <div>
              <h4 className="text-text-accent text-xs font-semibold mb-1 uppercase tracking-wider">AI Fix</h4>
              {!fix?.success && (
                <button
                  onClick={handleFix}
                  disabled={fixLoading}
                  className="border border-primary/40 bg-primary/10 text-text-accent hover:bg-primary/20 px-3 py-1.5 rounded-lg text-xs transition-colors disabled:opacity-50"
                >
                  {fixLoading ? "Generating fix…" : "Generate Fix"}
                </button>
              )}
              {fixError && <p className="text-critical text-xs mt-2 whitespace-pre-wrap">{fixError}</p>}
              {fix?.success && (
                <div className="space-y-2">
                  {fix.explanation && (
                    <p className="text-text-muted text-xs leading-relaxed whitespace-pre-wrap">{fix.explanation}</p>
                  )}
                  {fix.diff && (
                    <pre className="bg-bg-secondary border border-border rounded-xl p-3 text-xs overflow-x-auto font-mono text-text-muted whitespace-pre">
                      {fix.diff}
                    </pre>
                  )}
                </div>
              )}
            </div>
          )}
          <div className="flex gap-4 text-xs text-text-muted pt-1">
            <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
            {finding.priority && <span>Priority: P{finding.priority}</span>}
            {finding.impact && <span>Impact: {finding.impact}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
