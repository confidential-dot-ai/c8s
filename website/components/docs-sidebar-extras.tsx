import { ThemeToggle } from "./theme-toggle";

/** Docs sidebar footer: keep the single theme toggle available inside the docs.
 *  (The back-to-site link lives in the sidebar header — see lib/layout.shared.tsx.) */
export function DocsSidebarFooter() {
  return (
    <div className="flex flex-col gap-3 border-t border-fd-border pt-4">
      <ThemeToggle />
      <span className="font-mono text-[0.65rem] tracking-wide text-fd-muted-foreground">
        confidential ai
      </span>
    </div>
  );
}
