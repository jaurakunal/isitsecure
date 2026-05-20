export interface ScanHistoryEntry {
  scan_id: string;
  target_url: string | null;
  repo_url: string | null;
  scan_mode: string;
  started_at: string;
  grade: string | null;
  finding_count: number;
  critical_count: number;
  high_count: number;
}

const STORAGE_KEY = "isitsecure_history";

export function getScanHistory(): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function addScanToHistory(entry: ScanHistoryEntry) {
  const history = getScanHistory();
  history.unshift(entry);
  // Keep last 50 scans
  const trimmed = history.slice(0, 50);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
}
