import type { ReactNode } from 'react'

export type IconName = 'overview' | 'assets' | 'investigations' | 'incidents' | 'threat-model' | 'remediation' | 'reports' | 'integrity' | 'integrations' | 'admin' | 'menu' | 'collapse' | 'chevron'

const paths: Record<IconName, ReactNode> = {
  overview: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.5" /></>,
  assets: <><path d="m12 3 8.5 4.5L12 12 3.5 7.5 12 3Z" /><path d="m3.5 12 8.5 4.5 8.5-4.5M3.5 16.5 12 21l8.5-4.5" /></>,
  investigations: <><circle cx="11" cy="13" r="7.5" /><path d="m16.5 7.5 4-4M13 13l7.5-7.5M11 9v4l3 2" /><circle cx="11" cy="13" r="1" /></>,
  incidents: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
  'threat-model': <><path d="M12 3 3.5 20h17L12 3Z" /><path d="M12 9v4m0 3h.01" /></>,
  remediation: <><path d="M9 5h10a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V9" /><path d="m3.5 5.5 2 2 4-4M9 12h8m-8 4h8" /></>,
  reports: <><path d="M6 3.5h8l4 4V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 20V5a1.5 1.5 0 0 1 2-1.5Z" /><path d="M14 3.5V8h4M8 12h7m-7 4h7" /></>,
  integrity: <><path d="M12 3 4 6v5c0 5.2 3.4 8.8 8 10 4.6-1.2 8-4.8 8-10V6l-8-3Z" /><path d="m8.5 12 2.2 2.2 4.8-4.8" /></>,
  integrations: <><path d="M9 7V4m6 3V4M8 7h8a3 3 0 0 1 3 3v3a5 5 0 0 1-5 5h-1v3h-2v-3h-1a5 5 0 0 1-5-5v-3a3 3 0 0 1 3-3Z" /><path d="M9 11v2m6-2v2" /></>,
  admin: <><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.7a8 8 0 0 1-1.7 1l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.7-1l-1.7.7-1.4-2.4 1.4-1.1a7 7 0 0 1 0-2l-1.4-1.1 1.4-2.4 1.7.7a8 8 0 0 1 1.7-1l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.7 1l1.7-.7 1.4 2.4-1.4 1.1a7 7 0 0 1 0 2Z" /></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
  collapse: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16m6-11-2 3 2 3" /></>,
  chevron: <path d="m9 18 6-6-6-6" />,
}

export function Icon({ name, size = 20, className }: { name: IconName; size?: number; className?: string }) {
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{paths[name]}</svg>
}
