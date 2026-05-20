"use client";

import { useState } from "react";
import type { Finding } from "@/lib/api";
import { SeverityBadge } from "./SeverityBadge";

export function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="border border-border rounded-xl bg-bg-card hover:border-border-hover transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="p-4 flex items-start gap-3">
        <span className="text-text-muted text-sm mt-0.5 w-6 text-right shrink-0">
          {index}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-text-muted">{finding.scanner_name}</span>
            <span className="text-xs text-text-muted">|</span>
            <span className="text-xs text-text-muted">{finding.source}</span>
          </div>
          <h3 className="text-sm font-medium text-text truncate">{finding.title}</h3>
          {finding.code_location && (
            <p className="text-xs text-text-muted mt-1">
              {finding.code_location.file_path}
              {finding.code_location.line_number
                ? `:${finding.code_location.line_number}`
                : ""}
            </p>
          )}
          {finding.endpoint_url && (
            <p className="text-xs text-text-muted mt-1">
              {finding.http_method} {finding.endpoint_url}
            </p>
          )}
        </div>
        <span className="text-text-muted text-sm shrink-0">{expanded ? "−" : "+"}</span>
      </div>

      {expanded && (
        <div className="border-t border-border px-4 pb-4 pt-3 space-y-3 text-sm">
          {finding.description && (
            <div>
              <h4 className="text-text-accent text-xs font-medium mb-1">Description</h4>
              <p className="text-text-muted whitespace-pre-wrap">{finding.description}</p>
            </div>
          )}
          {finding.technical_detail && (
            <div>
              <h4 className="text-text-accent text-xs font-medium mb-1">Technical Detail</h4>
              <p className="text-text-muted whitespace-pre-wrap">{finding.technical_detail}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <h4 className="text-text-accent text-xs font-medium mb-1">Evidence</h4>
              <pre className="bg-bg-input border border-border rounded-lg p-3 text-xs overflow-x-auto">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation_guidance && (
            <div>
              <h4 className="text-text-accent text-xs font-medium mb-1">Remediation</h4>
              <p className="text-text-muted whitespace-pre-wrap">
                {finding.remediation_guidance}
              </p>
            </div>
          )}
          {finding.code_location?.code_snippet && (
            <div>
              <h4 className="text-text-accent text-xs font-medium mb-1">Code</h4>
              <pre className="bg-bg-input border border-border rounded-lg p-3 text-xs overflow-x-auto">
                {finding.code_location.code_snippet}
              </pre>
            </div>
          )}
          <div className="flex gap-4 text-xs text-text-muted">
            <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
            {finding.priority && <span>Priority: P{finding.priority}</span>}
            {finding.impact && <span>Impact: {finding.impact}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
