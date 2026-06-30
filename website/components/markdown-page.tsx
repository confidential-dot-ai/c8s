import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeRaw from "rehype-raw";
import rehypeSlug from "rehype-slug";
import Link from "next/link";
import { type ComponentPropsWithoutRef, type ReactNode } from "react";
import { CopyButton } from "./copy-button";

function isInternalLink(href: string): boolean {
  return (href.startsWith("/") && !href.startsWith("//")) || href.startsWith("#");
}

function MarkdownLink(props: ComponentPropsWithoutRef<"a">) {
  const { href, children, ...rest } = props;
  if (href && isInternalLink(href)) {
    return (
      <Link href={href} {...rest}>
        {children}
      </Link>
    );
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" {...rest}>
      {children}
    </a>
  );
}

function LinkIcon() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor" aria-hidden="true">
      <path d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-4.69 9.64a2 2 0 010-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-4.95 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25a.75.75 0 00-1.06-1.06l-1.25 1.25a2 2 0 01-2.83 0z" />
    </svg>
  );
}

type HeadingProps = ComponentPropsWithoutRef<"h1"> & { node?: unknown };

function makeHeading(Tag: "h1" | "h2" | "h3" | "h4") {
  return function MarkdownHeading({ node: _node, id, children, ...rest }: HeadingProps) {
    return (
      <Tag id={id} {...rest} className="group relative pl-6 -ml-6">
        {id && (
          <a
            href={`#${id}`}
            className="absolute left-0 inset-y-0 w-6 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity text-muted hover:text-foreground no-underline"
            aria-label="Link to section"
          >
            <LinkIcon />
          </a>
        )}
        {children}
      </Tag>
    );
  };
}

function getTextContent(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(getTextContent).join("");
  if (node && typeof node === "object" && "props" in node) {
    return getTextContent((node as { props: { children?: ReactNode } }).props.children);
  }
  return "";
}

export function MarkdownPage({ content }: { content: string }) {
  return (
    <article className="prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeRaw, rehypeSlug]}
        components={{
          a: MarkdownLink,
          h1: makeHeading("h1"),
          h2: makeHeading("h2"),
          h3: makeHeading("h3"),
          h4: makeHeading("h4"),
          pre: ({ children, ...rest }) => {
            const text = getTextContent(children);
            const isDiagram = /[┌┐└┘├┤┬┴┼│─═║╔╗╚╝╠╣╦╩╬]/.test(text);
            return (
              <div className="code-block">
                <CopyButton text={text} />
                <pre {...rest} className={isDiagram ? "w-fit" : undefined}>{children}</pre>
              </div>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </article>
  );
}
