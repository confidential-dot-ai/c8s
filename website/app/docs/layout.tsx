import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';
import { NativeFolder } from '@/components/native-folder';
import { DocsSidebarFooter } from '@/components/docs-sidebar-extras';

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <DocsLayout
      tree={source.getPageTree()}
      // Render folders as native <details> so expand/collapse never depends on
      // client-side hydration. Disable the desktop sidebar-collapse button.
      // The sidebar header (nav.title in layout.shared) is the back-to-site link.
      sidebar={{
        collapsible: false,
        components: { Folder: NativeFolder },
        footer: <DocsSidebarFooter />,
      }}
      themeSwitch={{ enabled: false }}
      {...baseOptions()}
    >
      {children}
    </DocsLayout>
  );
}
