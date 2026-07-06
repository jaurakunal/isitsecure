const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

export interface ScanRequest {
  target_url?: string;
  repo_url?: string;
  github_token?: string;
  branch?: string;
  scan_mode?: string;
  auth_email?: string;
  auth_password?: string;
  auth_provider?: string;
  llm_provider?: string;
  api_key?: string;
}

export interface ScanEvent {
  type: "progress" | "report" | "error" | "done";
  phase?: string;
  message?: string;
  progress?: number;
  data?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  source: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  technical_detail: string;
  evidence: string;
  confidence: number;
  scanner_name: string;
  impact: string | null;
  likelihood: string | null;
  priority: number | null;
  remediation_guidance: string;
  endpoint_url: string | null;
  http_method: string | null;
  code_location: {
    file_path: string;
    line_number: number | null;
    code_snippet: string;
  } | null;
}

export interface ScanReport {
  target_url: string | null;
  repo_url: string | null;
  repo_branch: string;
  framework: string;
  backend: string;
  scan_mode: string;
  total_endpoints_discovered: number;
  routes_in_code: number;
  tables_discovered: number;
  owner_summary: {
    grade: string;
    grade_label: string;
    risk_summary: string;
    key_risks: string[];
    remediation_phases: {
      phase_number: number;
      title: string;
      description: string;
    }[];
  } | null;
  findings: Finding[];
  scanners_run: string[];
  scan_duration_seconds: number;
  themes: { theme_id: string; title: string; severity: string; finding_count: number }[];
  token_usage: {
    input_tokens: number;
    output_tokens: number;
    estimated_cost_usd: number;
  } | null;
}

export async function startScan(request: ScanRequest): Promise<{ scan_id: string }> {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) throw new Error(`Scan failed: ${res.statusText}`);
  return res.json();
}

export function streamScan(
  scanId: string,
  onEvent: (event: ScanEvent) => void,
  onDone: () => void
) {
  const es = new EventSource(`${API_BASE}/api/scan/${scanId}/stream`);

  es.onmessage = (e) => {
    try {
      const event: ScanEvent = JSON.parse(e.data);
      onEvent(event);
      if (event.type === "done") {
        es.close();
        onDone();
      }
    } catch {
      // ignore parse errors
    }
  };

  es.onerror = () => {
    es.close();
    onDone();
  };

  return () => es.close();
}

export async function getReport(scanId: string): Promise<ScanReport> {
  const res = await fetch(`${API_BASE}/api/scan/${scanId}/report`);
  if (!res.ok) throw new Error(`Report not ready: ${res.statusText}`);
  return res.json();
}

/** URL of the self-contained HTML report for a scan (served by the backend). */
export function reportHtmlUrl(scanId: string): string {
  return `${API_BASE}/api/scan/${scanId}/report.html`;
}

export interface FixResult {
  success: boolean;
  diff: string;
  explanation: string;
  error: string | null;
}

/**
 * Ask the backend to generate an AI fix for a finding. The API key is
 * resolved server-side (env/config), so none is sent from the browser.
 */
export async function generateFix(
  findingId: string,
  fileContent: string,
  llmProvider = "anthropic"
): Promise<FixResult> {
  const res = await fetch(`${API_BASE}/api/fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      finding_id: findingId,
      file_content: fileContent,
      llm_provider: llmProvider,
    }),
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      if (j?.detail) msg = j.detail;
    } catch {
      // keep statusText
    }
    throw new Error(msg);
  }
  return res.json();
}
