const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(220, 38, 38, 0.15)", text: "#DC2626" },
  high: { bg: "rgba(234, 88, 12, 0.15)", text: "#EA580C" },
  medium: { bg: "rgba(202, 138, 4, 0.15)", text: "#CA8A04" },
  low: { bg: "rgba(22, 163, 74, 0.15)", text: "#16A34A" },
  info: { bg: "rgba(37, 99, 235, 0.15)", text: "#2563EB" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span
      className="px-2.5 py-0.5 rounded-full text-xs font-medium uppercase tracking-wide"
      style={{ background: colors.bg, color: colors.text }}
    >
      {severity}
    </span>
  );
}
