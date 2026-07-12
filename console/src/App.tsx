import { Suspense, lazy, useCallback, useEffect, useRef, useState, type ComponentType, type LazyExoticComponent, type MouseEvent } from 'react';
import CommandPalette, { type PaletteEntry } from './components/CommandPalette';
import NavRail, { type NavItem } from './components/NavRail';
import Topbar from './components/Topbar';
import { NAV_ICONS } from './components/navIcons';
import { api, apiErrorSummary, initCsrf } from './lib/api';
import { navigate, useHashRoute } from './lib/router';
import { roleLabel, useSession } from './lib/session';
import { useShellData } from './lib/shell';
import { toast } from './lib/toast';

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
const Licensing = lazy(() => import('./views/Licensing'));
const Policy = lazy(() => import('./views/Policy'));
const Deploy = lazy(() => import('./views/Deploy'));
const Integrations = lazy(() => import('./views/Integrations'));
const Audit = lazy(() => import('./views/Audit'));
const Updates = lazy(() => import('./views/Updates'));

interface Route extends NavItem {
  view: LazyExoticComponent<ComponentType>;
  allowedRoles?: string[];
}

interface RouteGroup {
  label: string;
  items: Route[];
}

const GROUPS: RouteGroup[] = [
  {
    label: 'Member Defense',
    items: [
      { path: '/', label: 'Texas FCU Overview', icon: NAV_ICONS.overview, view: Overview },
      { path: '/queue', label: 'Member Data Queue', icon: NAV_ICONS.queue, view: Queue },
      { path: '/monitor', label: 'FCU Command Center', icon: NAV_ICONS.monitor, view: Monitor },
      { path: '/activity', label: 'Exam Activity', icon: NAV_ICONS.activity, view: Activity },
    ],
  },
  {
    label: 'Risk & Proof',
    items: [
      { path: '/insights', label: 'Member Risk Insights', icon: NAV_ICONS.insights, view: Insights },
      { path: '/coverage', label: 'Texas FCU Coverage', icon: NAV_ICONS.coverage, view: Coverage },
      { path: '/lineage', label: 'Member Data Lineage', icon: NAV_ICONS.lineage, view: Lineage },
      { path: '/decision-quality', label: 'Reviewer Decisions', icon: NAV_ICONS.decisionQuality, view: DecisionQuality },
      { path: '/audit', label: 'Examiner Audit Chain', icon: NAV_ICONS.audit, view: Audit },
    ],
  },
  {
    label: 'Governance',
    items: [
      { path: '/catalog', label: 'AI Vendor Catalog', icon: NAV_ICONS.catalog, view: Catalog },
      { path: '/compliance', label: 'NCUA / GLBA Controls', icon: NAV_ICONS.compliance, view: Compliance },
      { path: '/ncua', label: 'Texas FCU Readiness', icon: NAV_ICONS.ncua, view: NcuaReadiness },
      { path: '/policy', label: 'Policy Configuration', icon: NAV_ICONS.policy, view: Policy },
    ],
  },
  {
    label: 'Administration',
    items: [
      { path: '/identity', label: 'Users & Roles', icon: NAV_ICONS.identity, view: Identity, allowedRoles: ['security_admin', 'operator', 'auditor'] },
      { path: '/licensing', label: 'Licensing', icon: NAV_ICONS.licensing, view: Licensing, allowedRoles: ['security_admin', 'operator', 'auditor'] },
      { path: '/deploy', label: 'Sensor Rollout', icon: NAV_ICONS.deploy, view: Deploy, allowedRoles: ['security_admin', 'operator'] },
      { path: '/integrations', label: 'Evidence Delivery', icon: NAV_ICONS.integrations, view: Integrations, allowedRoles: ['security_admin', 'operator'] },
      { path: '/updates', label: 'Controlled Updates', icon: NAV_ICONS.updates, view: Updates, allowedRoles: ['security_admin', 'operator'] },
    ],
  },
];

const ROUTES: Route[] = GROUPS.flatMap((group) => group.items);
const LEGACY_ACTIVITY_VIEWS_KEY = 'redactwall.savedViews';

function visibleGroupsForRole(role?: string | null): RouteGroup[] {
  return GROUPS
    .map((group) => ({
      ...group,
      items: group.items.filter((route) => !route.allowedRoles || route.allowedRoles.includes(role || '')),
    }))
    .filter((group) => group.items.length > 0);
}

async function signOut(): Promise<void> {
  const response = await api('/api/logout', { method: 'POST', allowAuthError: true });
  if (response?.status === 401) {
    await apiErrorSummary(response, '');
    window.location.href = '/login.html';
    return;
  }
  if (!response?.ok) {
    if (response) await apiErrorSummary(response, '');
    toast('Sign out failed. Your current session remains open.', 'error');
    return;
  }
  window.location.href = '/login.html';
}

// Keep palette theme changes on the same persisted control path as direct
// theme-toggle clicks.
function toggleColorTheme(): void {
  const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
  document.querySelector<HTMLButtonElement>(`.theme-toggle [data-theme-choice="${next}"]`)?.click();
}

const PALETTE_ACTIONS: PaletteEntry[] = [
  { group: 'Actions', label: 'Toggle color theme', icon: null, run: toggleColorTheme },
  { group: 'Actions', label: 'Sign out', icon: null, run: () => void signOut() },
];

function usePaletteHotkey(open: boolean, onOpen: () => void, onClose: () => void): void {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        if (open) onClose();
        else if (!document.querySelector('dialog[open]')) onOpen();
      }
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [onClose, onOpen, open]);
}

export default function App() {
  const route = useHashRoute();
  const { me, loading } = useSession();
  const [csrfReady, setCsrfReady] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const paletteButtonRef = useRef<HTMLButtonElement>(null);
  const shell = useShellData();

  useEffect(() => {
    initCsrf().finally(() => setCsrfReady(true));
  }, []);
  useEffect(() => {
    try {
      localStorage.removeItem(LEGACY_ACTIVITY_VIEWS_KEY);
    } catch {
      // Storage can be blocked; cleanup must not prevent the authenticated UI.
    }
  }, []);
  const visibleGroups = visibleGroupsForRole(me?.role);
  const visibleRoutes = visibleGroups.flatMap((group) => group.items);

  // Routes may carry a pivot query string (e.g. /activity?q=dest:host); match on
  // the path segment alone so a seeded deep link lands on the right view.
  const active = visibleRoutes.find((r) => r.path === route.split('?')[0]) ?? visibleRoutes[0] ?? ROUTES[0];
  const View = active.view;
  const who = loading ? 'Signing in…' : me ? `${me.user} / ${roleLabel(me.role)}` : 'Session unavailable';
  const closeNav = useCallback(() => setNavOpen(false), []);
  const openNav = useCallback(() => {
    setPaletteOpen(false);
    setNavOpen(true);
  }, []);
  const openPalette = useCallback(() => {
    setNavOpen(false);
    setPaletteOpen(true);
  }, []);
  const closePalette = useCallback(() => setPaletteOpen(false), []);
  usePaletteHotkey(paletteOpen, openPalette, closePalette);

  useEffect(() => closeNav(), [closeNav, route]);
  useEffect(() => {
    const desktop = window.matchMedia('(min-width: 901px)');
    const closeAtDesktop = () => {
      if (desktop.matches) closeNav();
    };
    closeAtDesktop();
    desktop.addEventListener('change', closeAtDesktop);
    return () => desktop.removeEventListener('change', closeAtDesktop);
  }, [closeNav]);

  const skipToContent = (event: MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    document.getElementById('main-content')?.focus({ preventScroll: false });
  };
  const paletteEntries: PaletteEntry[] = [
    ...visibleRoutes.map((visibleRoute) => ({
      group: 'Navigate',
      label: visibleRoute.label,
      icon: visibleRoute.icon,
      run: () => navigate(visibleRoute.path),
    })),
    ...PALETTE_ACTIONS,
  ];

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content" onClick={skipToContent}>Skip to main content</a>
      <NavRail
        groups={visibleGroups}
        activePath={active.path}
        held={shell.held}
        surfaces={shell.surfaces}
        postureState={shell.postureState}
        postureUpdatedAt={shell.lastUpdated}
        version={shell.version}
        mobileOpen={navOpen}
        returnFocusRef={menuButtonRef}
        onClose={closeNav}
      />
      <div className="app-main">
        <Topbar
          who={who}
          liveState={shell.liveState}
          postureState={shell.postureState}
          lastUpdated={shell.lastUpdated}
          routeLabel={active.label}
          contextLabel="Texas FCU · Authenticated console"
          navOpen={navOpen}
          menuButtonRef={menuButtonRef}
          paletteButtonRef={paletteButtonRef}
          onOpenNav={openNav}
          onOpenPalette={openPalette}
          onSignOut={() => void signOut()}
        />
        <main id="main-content" className="app-content" tabIndex={-1} aria-busy={!csrfReady}>
          {csrfReady ? (
            <Suspense fallback={<div className="app-loading">Loading view…</div>}>
              <View />
            </Suspense>
          ) : (
            <div className="app-loading">Preparing session…</div>
          )}
        </main>
      </div>
      {paletteOpen ? <CommandPalette entries={paletteEntries} returnFocusRef={paletteButtonRef} onClose={closePalette} /> : null}
    </div>
  );
}
