import type { ReactElement } from 'react';

/*
 * Rail tab icons, ported verbatim from the legacy console rail
 * (server/public/index.html). Keys match the route ids in App.tsx.
 * `decisionQuality` has no legacy tab; its glyph follows the same
 * 24px / 1.7-stroke style.
 */
export const NAV_ICONS = {
  overview: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 13a8 8 0 0 1 16 0M12 13l3.5-3.5M4 19h16" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  queue: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M5 5h14v5H5V5Zm0 9h14v5H5v-5Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" /></svg>
  ),
  monitor: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 12h4l2-6 4 12 2-6h4M5 19h14" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  activity: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 12h16M4 17h10" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>
  ),
  insights: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 20V4m0 16h16M8 20v-6m4 6V8m4 12v-9" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  coverage: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 19V5m0 14h16M8 16V9m5 7V6m5 10v-4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  lineage: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 7h5l2 3h9M4 17h5l2-3h9M9 7v10" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  decisionQuality: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M12 5a7 7 0 1 1 0 14 7 7 0 0 1 0-14Zm0 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" /></svg>
  ),
  catalog: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h16M8 6v12" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  compliance: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M9 12l2 2 4-4M12 3l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V6l7-3Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" /></svg>
  ),
  ncua: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M4 20h16M6 20v-9m4 9v-9m4 9v-9m4 9v-9M3 11l9-6 9 6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  identity: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8ZM4.5 20c.7-3.4 3.3-5.5 7.5-5.5s6.8 2.1 7.5 5.5M17 8h3m-1.5-1.5v3" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  policy: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M12 4l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V7l7-3Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" /></svg>
  ),
  deploy: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 19h14" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  integrations: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M7 8a3 3 0 0 1 3-3h1v6h-1a3 3 0 0 1-3-3ZM17 16a3 3 0 0 1-3 3h-1v-6h1a3 3 0 0 1 3 3ZM11 8h6M7 16h6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  audit: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M7 4h10v16H7V4Zm3 4h4m-4 4h6m-6 4h3" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
  updates: (
    <svg viewBox="0 0 24 24" fill="none"><path d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17.7 6.4H14M17.7 6.4V3M6.3 17.6H10M6.3 17.6V21" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  ),
} satisfies Record<string, ReactElement>;
