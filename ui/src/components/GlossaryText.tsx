"use client";

import { Fragment, type ReactNode } from "react";

/**
 * Render `text`, turning any glossary term that appears in it into a
 * dotted-underlined span with the plain-language definition as a hover
 * tooltip (native `title` attribute — no external deps, works in the static
 * export). Matching is case-insensitive and whole-word.
 */
export function GlossaryText({
  text,
  glossary,
  className,
}: {
  text: string;
  glossary?: Record<string, string> | null;
  className?: string;
}) {
  const terms = glossary ? Object.keys(glossary) : [];
  if (!text) return null;
  if (terms.length === 0) return <span className={className}>{text}</span>;

  // Build a single case-insensitive, whole-word regex for all terms, longest
  // first so multi-word terms win over their parts.
  const escaped = terms
    .sort((a, b) => b.length - a.length)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`\\b(${escaped.join("|")})\\b`, "gi");

  const parts: ReactNode[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index));
    const matched = match[0];
    const def = glossary?.[matched.toLowerCase()];
    if (def) {
      parts.push(
        <abbr
          key={key++}
          title={def}
          className="no-underline border-b border-dotted border-text-muted/60 cursor-help"
        >
          {matched}
        </abbr>
      );
    } else {
      parts.push(matched);
    }
    last = re.lastIndex;
  }
  if (last < text.length) parts.push(text.slice(last));

  return (
    <span className={className}>
      {parts.map((p, i) => (
        <Fragment key={i}>{p}</Fragment>
      ))}
    </span>
  );
}
