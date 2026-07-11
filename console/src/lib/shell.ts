import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchPosture, type PostureSurface } from '../api/posture';
import { asStats, fetchStats } from '../api/stats';
import { apiJson } from './api';

/**
 * Shell chrome telemetry, ported from the legacy dashboard's connectStream()/
 * loadStats()/loadPosture()/loadServerVersion(): one EventSource feeds the
 * queue badge, the rail posture chips, the LIVE indicator, and the LAST
 * UPDATED stamp. Views keep their own useEventStream subscriptions; the shell
 * needs onopen/onerror as well, which lib/sse.ts does not expose.
 */

export type LiveState = 'live' | 'reconnecting';

type StreamHandlers = Record<string, (data: unknown) => void>;

function useShellStream(handlers: StreamHandlers, onState: (state: LiveState) => void): void {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;
  const onStateRef = useRef(onState);
  onStateRef.current = onState;
  const eventNames = Object.keys(handlers).sort().join(',');

  useEffect(() => {
    const source = new EventSource('/api/stream');
    source.onopen = () => onStateRef.current('live');
    source.onerror = () => onStateRef.current('reconnecting');
    for (const name of eventNames ? eventNames.split(',') : []) {
      source.addEventListener(name, (event: MessageEvent) => {
        let data: unknown = null;
        try {
          data = JSON.parse(String(event.data));
        } catch {
          return;
        }
        handlersRef.current[name]?.(data);
      });
    }
    return () => source.close();
  }, [eventNames]);
}

export interface ShellData {
  pending: number;
  surfaces: PostureSurface[] | null;
  version: string;
  liveState: LiveState;
  lastUpdated: string;
}

function timestamp(): string {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function useShellData(): ShellData {
  const [pending, setPending] = useState(0);
  const [surfaces, setSurfaces] = useState<PostureSurface[] | null>(null);
  const [version, setVersion] = useState('-');
  const [liveState, setLiveState] = useState<LiveState>('live');
  const [lastUpdated, setLastUpdated] = useState('-');

  const refreshPosture = useCallback(async () => {
    const posture = await fetchPosture();
    if (!posture) {
      // Stats keep advancing LAST UPDATED, so a stale SECURE/MONITORING chip
      // would read as fresh; null returns the rail to its CHECKING state.
      setSurfaces(null);
      return;
    }
    setSurfaces(posture.surfaces ?? []);
    setLastUpdated(timestamp());
  }, []);

  const refresh = useCallback(async () => {
    const stats = await fetchStats();
    if (stats) {
      setPending(stats.pending);
      setLastUpdated(timestamp());
    }
    await refreshPosture();
  }, [refreshPosture]);

  const onStats = useCallback(
    (data: unknown) => {
      const stats = asStats(data);
      if (stats) {
        setPending(stats.pending);
        setLastUpdated(timestamp());
      }
      void refreshPosture();
    },
    [refreshPosture],
  );

  useEffect(() => {
    void refresh();
    void apiJson<{ version?: string }>('/healthz').then((body) => {
      if (body?.version) setVersion(String(body.version));
    });
  }, [refresh]);

  useShellStream({ query: () => void refresh(), decision: () => void refresh(), stats: onStats }, setLiveState);

  return { pending, surfaces, version, liveState, lastUpdated };
}
