const GRADE_COLORS: Record<string, { bg: string; text: string; shadow: string }> = {
  A: { bg: "rgba(22, 163, 74, 0.15)", text: "#16A34A", shadow: "0 0 20px rgba(22, 163, 74, 0.3)" },
  B: { bg: "rgba(37, 99, 235, 0.15)", text: "#2563EB", shadow: "0 0 20px rgba(37, 99, 235, 0.3)" },
  C: { bg: "rgba(202, 138, 4, 0.15)", text: "#CA8A04", shadow: "0 0 20px rgba(202, 138, 4, 0.3)" },
  D: { bg: "rgba(234, 88, 12, 0.15)", text: "#EA580C", shadow: "0 0 20px rgba(234, 88, 12, 0.3)" },
  F: { bg: "rgba(220, 38, 38, 0.15)", text: "#DC2626", shadow: "0 0 20px rgba(220, 38, 38, 0.3)" },
};

/**
 * Grade badge. Supports granular grades (A+, A-, C+, ...); color is chosen by
 * the base letter so A+/A/A- all share the "A" color. Pass `base` explicitly
 * (from the server's `grade_base`) to override; otherwise the first character
 * of `grade` is used.
 */
export function GradeBadge({
  grade,
  base,
  size = "lg",
}: {
  grade: string;
  base?: string;
  size?: "sm" | "lg";
}) {
  const colorKey = (base || grade?.[0] || "").toUpperCase();
  const colors = GRADE_COLORS[colorKey] || GRADE_COLORS.C;
  const sizeClass = size === "lg" ? "w-24 h-24" : "w-10 h-10";
  // Granular grades ("A+", "C+") need smaller type to fit the badge.
  const multiChar = (grade?.length || 0) > 1;
  const textClass =
    size === "lg" ? (multiChar ? "text-4xl" : "text-5xl") : multiChar ? "text-base" : "text-xl";

  return (
    <div
      className={`${sizeClass} ${textClass} rounded-2xl border flex items-center justify-center font-bold shrink-0`}
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
