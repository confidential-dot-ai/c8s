"use client";

import { useEffect, useState, useRef } from "react";

export interface TocItem {
  id: string;
  text: string;
  level: number;
  /** Optional path for cross-page links. When set, the entry links to `${href}#${id}` (or just `${href}` if id is empty) and is excluded from in-page scrollspy. */
  href?: string;
}

export function TableOfContents({ items }: { items: TocItem[] }) {
  const [activeId, setActiveId] = useState<string>("");
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    const headings = items
      .filter((item) => !item.href)
      .map((item) => document.getElementById(item.id))
      .filter(Boolean) as HTMLElement[];

    if (headings.length === 0) return;

    observerRef.current = new IntersectionObserver(
      (entries) => {
        // Find the first heading that is intersecting (visible)
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length > 0) {
          // Pick the one closest to the top
          visible.sort(
            (a, b) => a.boundingClientRect.top - b.boundingClientRect.top
          );
          setActiveId(visible[0].target.id);
        }
      },
      {
        rootMargin: "-80px 0px -60% 0px",
        threshold: 0,
      }
    );

    headings.forEach((h) => observerRef.current!.observe(h));

    return () => observerRef.current?.disconnect();
  }, [items]);

  function handleClick(e: React.MouseEvent<HTMLAnchorElement>, id: string) {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
      setActiveId(id);
      history.replaceState(null, "", `#${id}`);
    }
  }

  return (
    <nav
      aria-label="Table of contents"
      className="hidden xl:block fixed top-16 right-6 w-56 max-h-[calc(100vh-6rem)] overflow-y-auto text-xs leading-relaxed"
    >
      <ul className="flex flex-col gap-0.5 border-l border-border pl-3">
        {items.map((item, idx) => {
          const isCrossPage = Boolean(item.href);
          const href = isCrossPage
            ? `${item.href}${item.id ? `#${item.id}` : ""}`
            : `#${item.id}`;
          const indent = item.level === 3 ? "pl-3" : item.level === 4 ? "pl-6" : "";
          return (
            <li key={`${item.href ?? ""}#${item.id}-${idx}`}>
              <a
                href={href}
                onClick={isCrossPage ? undefined : (e) => handleClick(e, item.id)}
                className={`block py-0.5 transition-colors no-underline hover:text-foreground ${indent} ${
                  !isCrossPage && activeId === item.id
                    ? "text-accent"
                    : item.level === 2 ? "text-heading" : "text-muted"
                }`}
              >
                {item.text}
              </a>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
