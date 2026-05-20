const GRADE_COLORS: Record<string, { bg: string; text: string; shadow: string }> = {
  A: { bg: "rgba(22, 163, 74, 0.15)", text: "#16A34A", shadow: "0 0 20px rgba(22, 163, 74, 0.3)" },
  B: { bg: "rgba(37, 99, 235, 0.15)", text: "#2563EB", shadow: "0 0 20px rgba(37, 99, 235, 0.3)" },
  C: { bg: "rgba(202, 138, 4, 0.15)", text: "#CA8A04", shadow: "0 0 20px rgba(202, 138, 4, 0.3)" },
  D: { bg: "rgba(234, 88, 12, 0.15)", text: "#EA580C", shadow: "0 0 20px rgba(234, 88, 12, 0.3)" },
  F: { bg: "rgba(220, 38, 38, 0.15)", text: "#DC2626", shadow: "0 0 20px rgba(220, 38, 38, 0.3)" },
};

export function GradeBadge({ grade, size = "lg" }: { grade: string; size?: "sm" | "lg" }) {
  const colors = GRADE_COLORS[grade?.[0]] || GRADE_COLORS.C;
  const sizeClass = size === "lg" ? "text-5xl w-24 h-24" : "text-xl w-10 h-10";

  return (
    <div
      className={`${sizeClass} rounded-2xl border flex items-center justify-center font-bold`}
      style={{
        background: colors.bg,
        color: colors.text,
        borderColor: `${colors.text}33`,
        boxShadow: colors.shadow,
      }}
    >
      {grade || "?"}
    </div>
  );
}
