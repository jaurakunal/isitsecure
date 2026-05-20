"use client";

import { useEffect, useState } from "react";
import { getScanHistory, type ScanHistoryEntry } from "@/lib/storage";
import { GradeBadge } from "@/components/GradeBadge";

export default function History() {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  return (
    <div className="max-w-4xl mx-auto px-6 py-12">
      <h1 className="text-2xl font-bold text-text-accent mb-2">Scan History</h1>
      <p className="text-text-muted text-sm mb-8">
        Previous scans stored locally in your browser.
      </p>

      {history.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <p className="text-text-muted mb-4">No scans yet.</p>
          <a
            href="/"
            className="btn-primary inline-block"
          >
            Start Your First Scan
          </a>
        </div>
      ) : (
        <div className="space-y-3">
          {history.map((entry) => (
            <a
              key={entry.scan_id}
              href={`/report/?id=${entry.scan_id}`}
              className="glass-card p-4 flex items-center gap-4 block"
            >
              <GradeBadge grade={entry.grade || "?"} size="sm" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-text truncate">
                  {entry.target_url || entry.repo_url || "Unknown target"}
                </div>
                <div className="text-xs text-text-muted mt-0.5">
                  {entry.scan_mode} | {entry.finding_count} findings |{" "}
                  {new Date(entry.started_at).toLocaleString()}
                </div>
              </div>
              <div className="flex gap-3 text-xs shrink-0">
                {entry.critical_count > 0 && (
                  <span className="text-critical font-medium">
                    {entry.critical_count} critical
                  </span>
                )}
                {entry.high_count > 0 && (
                  <span className="text-high font-medium">
                    {entry.high_count} high
                  </span>
                )}
              </div>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
