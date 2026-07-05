import { useEffect, useRef } from 'react';

type EventHandlers = Record<string, (data: unknown) => void>;

/**
 * Subscribe to the server's live event stream (/api/stream). EventSource
 * reconnects on its own; handlers receive parsed JSON payloads. Handlers are
 * kept in a ref so callers can pass fresh closures without re-connecting.
 */
export function useEventStream(handlers: EventHandlers): void {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;
  const eventNames = Object.keys(handlers).sort().join(',');

  useEffect(() => {
    const source = new EventSource('/api/stream');
    const names = eventNames ? eventNames.split(',') : [];
    for (const name of names) {
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
