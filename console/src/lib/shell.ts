import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchPostureResult, type PostureSurface } from '../api/posture';
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
export type PostureState = 'loading' | 'ready' | 'stale' | 'unavailable';

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
  /** Combined held count. Null means an older backend did not report it. */
  held: number | null | undefined;
  surfaces: PostureSurface[] | null;
  version: string;
  liveState: LiveState;
  /** Freshness of the posture-backed rail indicators, independent of SSE health. */
  postureState: PostureState;
  /** Time of the last successful posture response, never a stats-only update. */
  lastUpdated: string;
}

function timestamp(): string {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function useShellData(): ShellData {
  const [held, setHeld] = useState<number | null | undefined>(undefined);
  const [surfaces, setSurfaces] = useState<PostureSurface[] | null>(null);
  const [version, setVersion] = useState('-');
  const [liveState, setLiveState] = useState<LiveState>('reconnecting');
  const [postureState, setPostureState] = useState<PostureState>('loading');
  const [lastUpdated, setLastUpdated] = useState('-');
  const statsRequestRef = useRef(0);
  const postureRequestRef = useRef(0);
  const hasPostureRef = useRef(false);

  const refreshPosture = useCallback(async () => {
    const requestId = ++postureRequestRef.current;
    const result = await fetchPostureResult();
    if (requestId !== postureRequestRef.current) return;
    if (!result.ok || !Array.isArray(result.report.surfaces)) {
      setPostureState(hasPostureRef.current ? 'stale' : 'unavailable');
      return;
    }
    hasPostureRef.current = true;
    setSurfaces(result.report.surfaces);
    setPostureState('ready');
    setLastUpdated(timestamp());
  }, []);

  const refresh = useCallback(async () => {
    const requestId = ++statsRequestRef.current;
    const stats = await fetchStats();
    if (requestId === statsRequestRef.current && stats) {
      setHeld(stats.held);
    }
    await refreshPosture();
  }, [refreshPosture]);

  const onStats = useCallback(
    (data: unknown) => {
      const stats = asStats(data);
      if (stats) {
        statsRequestRef.current += 1;
        setHeld(stats.held);
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

  return { held, surfaces, version, liveState, postureState, lastUpdated };
}
