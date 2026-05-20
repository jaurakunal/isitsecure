const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-critical/20 text-critical",
  high: "bg-high/20 text-high",
  medium: "bg-medium/20 text-medium",
  low: "bg-low/20 text-low",
  info: "bg-info/20 text-info",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.info;
  return (
    <span className={`${style} px-2 py-0.5 rounded text-xs font-medium uppercase`}>
      {severity}
    </span>
  );
}
