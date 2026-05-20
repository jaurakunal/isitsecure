const GRADE_COLORS: Record<string, string> = {
  A: "bg-success/20 text-success border-success/30",
  B: "bg-low/20 text-low border-low/30",
  C: "bg-medium/20 text-medium border-medium/30",
  D: "bg-high/20 text-high border-high/30",
  F: "bg-critical/20 text-critical border-critical/30",
};

export function GradeBadge({ grade, size = "lg" }: { grade: string; size?: "sm" | "lg" }) {
  const color = GRADE_COLORS[grade?.[0]] || GRADE_COLORS.C;
  const sizeClass = size === "lg" ? "text-5xl w-24 h-24" : "text-xl w-10 h-10";

  return (
    <div
      className={`${color} ${sizeClass} rounded-xl border-2 flex items-center justify-center font-bold`}
    >
      {grade || "?"}
    </div>
  );
}
