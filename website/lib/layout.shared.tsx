import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { ArrowLeft } from 'lucide-react';
import { Logo } from '@/components/logo';

const GITHUB_URL = 'https://github.com/confidential-dot-ai';

/**
 * Shared docs layout config. The sidebar header doubles as the "back to site"
 * control: a back arrow + the Confidential AI wordmark, linking home. (This is
 * the single brand mark in the docs chrome — no separate banner.)
 */
export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      url: '/',
      title: (
        <span className="inline-flex items-center gap-2 text-heading">
          <ArrowLeft size={16} className="text-muted" />
          <Logo height={20} />
        </span>
      ),
      transparentMode: 'top',
    },
    githubUrl: GITHUB_URL,
  };
}
