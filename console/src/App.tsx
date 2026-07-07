import { Suspense, lazy, useCallback, useEffect, useState, type ComponentType, type Dispatch, type LazyExoticComponent, type SetStateAction } from 'react';
import CommandPalette, { type PaletteEntry } from './components/CommandPalette';
import NavRail, { type NavItem } from './components/NavRail';
import Topbar from './components/Topbar';
import { NAV_ICONS } from './components/navIcons';
import { apiJson, initCsrf } from './lib/api';
import { navigate, useHashRoute } from './lib/router';
import { roleLabel, useSession } from './lib/session';
import { useShellData } from './lib/shell';

const Overview = lazy(() => import('./views/Overview'));
const Queue = lazy(() => import('./views/Queue'));
const Monitor = lazy(() => import('./views/Monitor'));
const Activity = lazy(() => import('./views/Activity'));
const Insights = lazy(() => import('./views/Insights'));
const Coverage = lazy(() => import('./views/Coverage'));
const Lineage = lazy(() => import('./views/Lineage'));
const DecisionQuality = lazy(() => import('./views/DecisionQuality'));
const Catalog = lazy(() => import('./views/Catalog'));
const Compliance = lazy(() => import('./views/Compliance'));
const NcuaReadiness = lazy(() => import('./views/NcuaReadiness'));
const Identity = lazy(() => import('./views/Identity'));
const Policy = lazy(() => import('./views/Policy'));
const Deploy = lazy(() => import('./views/Deploy'));
const Integrations = lazy(() => import('./views/Integrations'));
const Audit = lazy(() => import('./views/Audit'));
const Updates = lazy(() => import('./views/Updates'));

interface Route extends NavItem {
  view: LazyExoticComponent<ComponentType>;
}

interface RouteGroup {
  label: string;
  items: Route[];
}

const GROUPS: RouteGroup[] = [
  {
    label: 'Operate',
    items: [
      { path: '/', label: 'Overview', icon: NAV_ICONS.overview, view: Overview },
      { path: '/queue', label: 'Approval Queue', icon: NAV_ICONS.queue, view: Queue },
      { path: '/monitor', label: 'AI Command Center', icon: NAV_ICONS.monitor, view: Monitor },
      { path: '/activity', label: 'All Activity', icon: NAV_ICONS.activity, view: Activity },
    ],
  },
  {
    label: 'Analyze',
    items: [
      { path: '/insights', label: 'Insights', icon: NAV_ICONS.insights, view: Insights },
      { path: '/coverage', label: 'Sensor Coverage', icon: NAV_ICONS.coverage, view: Coverage },
      { path: '/lineage', label: 'Data Lineage', icon: NAV_ICONS.lineage, view: Lineage },
      { path: '/decision-quality', label: 'Decision Quality', icon: NAV_ICONS.decisionQuality, view: DecisionQuality },
    ],
  },
  {
    label: 'Govern',
    items: [
      { path: '/catalog', label: 'App Catalog', icon: NAV_ICONS.catalog, view: Catalog },
      { path: '/compliance', label: 'Compliance', icon: NAV_ICONS.compliance, view: Compliance },
      { path: '/ncua', label: 'NCUA Readiness', icon: NAV_ICONS.ncua, view: NcuaReadiness },
      { path: '/identity', label: 'Identity', icon: NAV_ICONS.identity, view: Identity },
      { path: '/policy', label: 'Configuration', icon: NAV_ICONS.policy, view: Policy },
    ],
  },
  {
    label: 'System',
    items: [
      { path: '/deploy', label: 'Deploy', icon: NAV_ICONS.deploy, view: Deploy },
      { path: '/integrations', label: 'Integrations', icon: NAV_ICONS.integrations, view: Integrations },
      { path: '/audit', label: 'Audit Log', icon: NAV_ICONS.audit, view: Audit },
      { path: '/updates', label: 'Updates', icon: NAV_ICONS.updates, view: Updates },
    ],
  },
];

const ROUTES: Route[] = GROUPS.flatMap((group) => group.items);

async function signOut(): Promise<void> {
  await apiJson('/api/logout', { method: 'POST' });
  window.location.href = '/login.html';
}

// Legacy palette parity: flip the theme by clicking the ThemeToggle button so
// its pressed state stays in sync with the shared body[data-theme] attribute.
function toggleColorTheme(): void {
  const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
  document.querySelector<HTMLButtonElement>(`.theme-toggle [data-theme-choice="${next}"]`)?.click();
}

const PALETTE_ENTRIES: PaletteEntry[] = [
  ...ROUTES.map((route) => ({ group: 'Navigate', label: route.label, icon: route.icon, run: () => navigate(route.path) })),
  { group: 'Actions', label: 'Toggle color theme', icon: null, run: toggleColorTheme },
  { group: 'Actions', label: 'Sign out', icon: null, run: () => void signOut() },
];

function usePaletteHotkey(setOpen: Dispatch<SetStateAction<boolean>>): void {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen((open) => !open);
      }
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [setOpen]);
}

export default function App() {
  const route = useHashRoute();
  const { me, loading } = useSession();
  const [csrfReady, setCsrfReady] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const shell = useShellData();

  useEffect(() => {
    initCsrf().finally(() => setCsrfReady(true));
  }, []);
  usePaletteHotkey(setPaletteOpen);

  // Routes may carry a pivot query string (e.g. /activity?q=dest:host); match on
  // the path segment alone so a seeded deep link lands on the right view.
  const active = ROUTES.find((r) => r.path === route.split('?')[0]) ?? ROUTES[0];
  const View = active.view;
  const who = loading ? 'Signing in…' : me ? `${me.user} / ${roleLabel(me.role)}` : 'Session unavailable';
  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const closePalette = useCallback(() => setPaletteOpen(false), []);

  return (
    <div className="app-shell">
      <NavRail groups={GROUPS} activePath={active.path} pending={shell.pending} surfaces={shell.surfaces} version={shell.version} />
      <div className="app-main">
        <Topbar who={who} liveState={shell.liveState} lastUpdated={shell.lastUpdated} onOpenPalette={openPalette} onSignOut={() => void signOut()} />
        <main className="app-content">
          {csrfReady ? (
            <Suspense fallback={<div className="app-loading">Loading view…</div>}>
              <View />
            </Suspense>
          ) : (
            <div className="app-loading">Preparing session…</div>
          )}
        </main>
      </div>
      {paletteOpen ? <CommandPalette entries={PALETTE_ENTRIES} onClose={closePalette} /> : null}
    </div>
  );
}
