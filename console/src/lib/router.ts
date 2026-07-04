import { useEffect, useState } from 'react';

/**
 * Hash-based routing keeps deep links working without an Express catch-all:
 * /app/#/queue survives refresh because the server only ever sees /app/.
 */

function currentRoute(): string {
  const hash = location.hash.replace(/^#/, '');
  if (!hash || hash === '/') return '/';
  return hash.startsWith('/') ? hash : `/${hash}`;
}

export function useHashRoute(): string {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const onChange = () => setRoute(currentRoute());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

export function navigate(path: string): void {
  location.hash = path.startsWith('/') ? path : `/${path}`;
}

export function routeHref(path: string): string {
  return `#${path.startsWith('/') ? path : `/${path}`}`;
}
