"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { startScan } from "@/lib/api";

const SCAN_MODES = [
  { id: "auto", label: "Auto Detect", description: "Picks best mode from what you provide" },
  { id: "url_only", label: "URL Only", description: "Dynamic testing of your live app" },
  { id: "code_only", label: "Code Only", description: "Static analysis of your source code" },
  { id: "full", label: "Full Scan", description: "SAST + DAST + AI review — everything" },
];

export default function Home() {
  const router = useRouter();
  const [targetUrl, setTargetUrl] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [scanMode, setScanMode] = useState("auto");
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [apiKey, setApiKey] = useState("");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authProvider, setAuthProvider] = useState("supabase");
  const [showAuth, setShowAuth] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!targetUrl && !repoUrl) {
      setError("Provide a target URL, a repo URL, or both.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const { scan_id } = await startScan({
        target_url: targetUrl || undefined,
        repo_url: repoUrl || undefined,
        github_token: githubToken || undefined,
        scan_mode: scanMode === "auto" ? undefined : scanMode,
        llm_provider: llmProvider,
        api_key: apiKey || undefined,
        auth_email: showAuth ? authEmail || undefined : undefined,
        auth_password: showAuth ? authPassword || undefined : undefined,
        auth_provider: showAuth ? authProvider : undefined,
      });
      router.push(`/scan/?id=${scan_id}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start scan");
      setLoading(false);
    }
  };

  const estimatedCost =
    scanMode === "url_only" ? "$0"
    : scanMode === "code_only" && apiKey ? "~$5-8"
    : scanMode === "full" && apiKey ? "~$10-15"
    : apiKey ? "~$5-15" : "$0";

  const inputClass = "w-full bg-bg-input border border-border rounded-lg px-4 py-2.5 text-text placeholder:text-text-muted/40 focus:outline-none focus:border-border-hover transition-colors";

  return (
    <div className="max-w-2xl mx-auto px-6 py-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl font-bold text-text-accent mb-2">Scan Your App</h1>
        <p className="text-text-muted">29 security scanners. SAST + DAST + AI review. One click.</p>
      </div>

      <div className="space-y-6">
        <div>
          <label className="block text-sm text-text-muted mb-1.5">Target URL <span className="text-text-muted/60">(for dynamic testing)</span></label>
          <input type="url" placeholder="https://your-app.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} className={inputClass} />
        </div>

        <div>
          <label className="block text-sm text-text-muted mb-1.5">GitHub Repo <span className="text-text-muted/60">(for code analysis)</span></label>
          <input type="text" placeholder="https://github.com/you/your-app" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} className={inputClass} />
          {repoUrl && <input type="password" placeholder="GitHub token (for private repos)" value={githubToken} onChange={e => setGithubToken(e.target.value)} className={`${inputClass} mt-2`} />}
        </div>

        <div>
          <label className="block text-sm text-text-muted mb-2">Scan Mode</label>
          <div className="grid grid-cols-2 gap-2">
            {SCAN_MODES.map(mode => (
              <button key={mode.id} onClick={() => setScanMode(mode.id)} className={`border rounded-lg p-3 text-left transition-colors ${scanMode === mode.id ? "border-primary bg-primary/10 text-text-accent" : "border-border bg-bg-card text-text-muted hover:border-border-hover"}`}>
                <div className="text-sm font-medium">{mode.label}</div>
                <div className="text-xs text-text-muted/70 mt-0.5">{mode.description}</div>
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm text-text-muted mb-1.5">AI Provider <span className="text-text-muted/60">(for business logic review)</span></label>
          <div className="flex gap-2 mb-2">
            {["anthropic", "google", "none"].map(p => (
              <button key={p} onClick={() => setLlmProvider(p)} className={`border rounded-lg px-4 py-2 text-sm transition-colors ${llmProvider === p ? "border-primary bg-primary/10 text-text-accent" : "border-border bg-bg-card text-text-muted hover:border-border-hover"}`}>
                {p === "none" ? "None (free)" : p === "anthropic" ? "Anthropic" : "Google"}
              </button>
            ))}
          </div>
          {llmProvider !== "none" && <input type="password" placeholder={`${llmProvider === "anthropic" ? "ANTHROPIC" : "GOOGLE"}_API_KEY`} value={apiKey} onChange={e => setApiKey(e.target.value)} className={inputClass} />}
        </div>

        <div>
          <button onClick={() => setShowAuth(!showAuth)} className="text-sm text-text-muted hover:text-text-accent transition-colors">
            {showAuth ? "−" : "+"} Login Credentials <span className="text-text-muted/60">(for authenticated scanning)</span>
          </button>
          {showAuth && (
            <div className="mt-3 space-y-2 p-4 border border-border rounded-lg bg-bg-card">
              <select value={authProvider} onChange={e => setAuthProvider(e.target.value)} className={inputClass}>
                <option value="supabase">Supabase</option>
                <option value="firebase">Firebase</option>
                <option value="browser">Browser (form fill)</option>
                <option value="token">Direct Token</option>
              </select>
              <input type="email" placeholder="Email" value={authEmail} onChange={e => setAuthEmail(e.target.value)} className={inputClass} />
              <input type="password" placeholder="Password" value={authPassword} onChange={e => setAuthPassword(e.target.value)} className={inputClass} />
            </div>
          )}
        </div>

        {error && <div className="p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">{error}</div>}

        <div className="flex items-center justify-between pt-2">
          <span className="text-sm text-text-muted">Estimated cost: <span className="text-text-accent font-medium">{estimatedCost}</span></span>
          <button onClick={handleScan} disabled={loading} className="bg-primary hover:bg-primary-hover disabled:opacity-50 text-white font-medium px-8 py-2.5 rounded-lg transition-colors">
            {loading ? "Starting..." : "Start Scan"}
          </button>
        </div>
      </div>
    </div>
  );
}
