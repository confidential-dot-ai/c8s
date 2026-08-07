import type { Metadata } from "next";
import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";
import { notFound } from "next/navigation";
import fs from "fs";
import path from "path";

const DOCS_ROOT = path.resolve(process.cwd(), "..", "docs");

const VALID_SLUG_SEGMENT = /^[\w-]+$/;

// Map URL slugs to file paths relative to docs/
function resolveDocPath(slug: string[]): string | null {
  // Validate each slug segment to prevent path traversal
  if (!slug.every((s) => VALID_SLUG_SEGMENT.test(s))) {
    return null;
  }

  const joined = slug.join("/");

  // Retain the historical source document without publishing a route for it.
  if (joined === "confidential-agents-api") {
    return null;
  }

  // Direct file match: e.g., intro-to-tees -> intro-to-tees.md
  const directFile = path.join(DOCS_ROOT, joined + ".md");
  if (fs.existsSync(directFile)) {
    return "docs/" + joined + ".md";
  }

  // Directory with README: e.g., confidential-computing-primer -> confidential-computing-primer/README.md
  const readmeFile = path.join(DOCS_ROOT, joined, "README.md");
  if (fs.existsSync(readmeFile)) {
    return "docs/" + joined + "/README.md";
  }

  return null;
}

export function generateStaticParams() {
  const params: { slug: string[] }[] = [];

  function walk(dir: string, prefix: string[]) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const readmePath = path.join(dir, entry.name, "README.md");
        if (fs.existsSync(readmePath)) {
          params.push({ slug: [...prefix, entry.name] });
        }
        walk(path.join(dir, entry.name), [...prefix, entry.name]);
      } else if (entry.name.endsWith(".md") && entry.name !== "README.md") {
        const name = entry.name.replace(/\.md$/, "");
        if (prefix.length === 0 && name === "confidential-agents-api") {
          continue;
        }
        params.push({ slug: [...prefix, name] });
      }
    }
  }

  walk(DOCS_ROOT, []);
  return params;
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string[] }> }): Promise<Metadata> {
  const { slug } = await params;
  const docPath = resolveDocPath(slug);
  if (!docPath) return {};
  const raw = fs.readFileSync(path.resolve(process.cwd(), "..", docPath), "utf-8");
  const match = raw.match(/^#\s+(.+)$/m);
  return match ? { title: match[1].trim() } : {};
}

export default async function DocPage({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params;
  const docPath = resolveDocPath(slug);

  if (!docPath) {
    notFound();
  }

  const content = getMarkdownContent(docPath);
  return <MarkdownPageWithToc content={content} />;
}
