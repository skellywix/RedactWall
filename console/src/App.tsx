import { Suspense, lazy, useEffect, useState, type ComponentType, type LazyExoticComponent } from 'react';
import { initCsrf } from './lib/api';
import { routeHref, useHashRoute } from './lib/router';
import { roleLabel, useSession } from './lib/session';

const Overview = lazy(() => import('./views/Overview'));
const Queue = lazy(() => import('./views/Queue'));
const Policy = lazy(() => import('./views/Policy'));
const Audit = lazy(() => import('./views/Audit'));
const DecisionQuality = lazy(() => import('./views/DecisionQuality'));

interface Route {
  path: string;
  label: string;
  view: LazyExoticComponent<ComponentType>;
}

const ROUTES: Route[] = [
  { path: '/', label: 'Overview', view: Overview },
  { path: '/queue', label: 'Approval Queue', view: Queue },
  { path: '/policy', label: 'Policy', view: Policy },
  { path: '/audit', label: 'Audit', view: Audit },
  { path: '/decision-quality', label: 'Decision Quality', view: DecisionQuality },
];

export default function App() {
  const route = useHashRoute();
  const { me, loading } = useSession();
  const [csrfReady, setCsrfReady] = useState(false);

  useEffect(() => {
    initCsrf().finally(() => setCsrfReady(true));
  }, []);

  const active = ROUTES.find((r) => r.path === route) ?? ROUTES[0];
  const View = active.view;

  return (
    <div className="app-shell">
      <aside className="app-rail">
        <div className="app-brand">
          <span className="app-brand-name">PromptWall</span>
          <span className="app-brand-sub">Security Console</span>
        </div>
        <nav aria-label="Console sections">
          {ROUTES.map((r) => (
            <a key={r.path} href={routeHref(r.path)} className={r.path === active.path ? 'app-nav active' : 'app-nav'}>
              {r.label}
            </a>
          ))}
        </nav>
        <a className="app-nav app-nav-legacy" href="/index.html">
          Classic console
        </a>
      </aside>
      <div className="app-main">
        <header className="app-topbar">
          <span id="who" className="app-who">
            {loading ? 'Signing in…' : me ? `${me.user} / ${roleLabel(me.role)}` : 'Session unavailable'}
          </span>
        </header>
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
    </div>
  );
}
