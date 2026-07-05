import { useEffect, useMemo, useState } from 'react';
import type {
  LeakMapEdge,
  LeakMapNode,
  LeakMapReport,
  PostureSurface,
} from '../../api/posture';
import { routeHref } from '../../lib/router';
import './LeakMap.css';

/* Geometry mirrors the classic console's leak-path-map.js so both consoles
   read the same posture.leakMap contract identically. */
const W = 1000;
const SEG_X = 234;
const CH_L = 436;
const CH_R = 564;
const DEST_X = 766;
const NODE_W = 224;
const NODE_H = 52;
const CH_W = 128;
const CH_H = 46;
const PAD_TOP = 52;
const PAD_BOT = 18;
const ROW_H = 78;

type Filter = 'all' | 'risk' | 'shadow';
type Selection = { kind: 'edge'; id: string } | { kind: 'node'; id: string };

const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'All flows' },
  { id: 'risk', label: 'At-risk' },
  { id: 'shadow', label: 'Shadow AI' },
];

const num = (v: unknown): number => {
  const x = Number(v);
  return Number.isFinite(x) && x > 0 ? Math.round(x) : 0;
};
const trim = (value: string, max: number): string =>
  value.length > max ? `${value.slice(0, max - 1)}…` : value;
const plural = (count: number, word: string): string => `${count} ${word}${count === 1 ? '' : 's'}`;

function useReducedMotion(): boolean {
  const [still, setStill] = useState(() => {
    try {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      return false;
    }
  });
  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setStill(media.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);
  return still;
}

function edgeVisible(edge: LeakMapEdge, filter: Filter, category: string, dests: Map<string, LeakMapNode>): boolean {
  if (filter === 'risk' && !(num(edge.uncontrolled) || num(edge.shadow) || num(edge.pending))) return false;
  if (filter === 'shadow' && !(num(edge.shadow) || dests.get(edge.to)?.state === 'shadow')) return false;
  if (category && !(edge.categories || []).some((item) => item.label === category)) return false;
  return true;
}

function edgeTone(edge: LeakMapEdge, dests: Map<string, LeakMapNode>): string {
  if (num(edge.shadow) || dests.get(edge.to)?.state === 'shadow') return 'is-shadow';
  if (num(edge.uncontrolled)) return 'is-leak';
  if (num(edge.pending)) return 'is-held';
  return 'is-clean';
}

const edgeWidth = (edge: LeakMapEdge): number =>
  Number((1.6 + Math.min(4.4, Math.log2(num(edge.events) + 1))).toFixed(1));

const yFor = (index: number, count: number, height: number): number =>
  PAD_TOP + (height - PAD_TOP - PAD_BOT) * ((index + 0.5) / Math.max(1, count));

function destKicker(dest: LeakMapNode): string {
  const state = String(dest.state || 'observed');
  if (state === 'sanctioned') return 'GOVERNED';
  if (state === 'shadow') return 'SHADOW AI';
  if (state === 'unsanctioned') return 'UNSANCTIONED';
  return state.toUpperCase();
}

function nodeSub(item: LeakMapNode | LeakMapEdge): string {
  const parts: string[] = [];
  if (num(item.uncontrolled)) parts.push(`${num(item.uncontrolled)} uncontrolled`);
  if (num(item.shadow)) parts.push(`${num(item.shadow)} shadow`);
  if (num(item.pending)) parts.push(`${num(item.pending)} held`);
  if (!parts.length && num(item.redacted)) parts.push(`${num(item.redacted)} redacted`);
  if (!parts.length && num(item.blocked)) parts.push(`${num(item.blocked)} stopped`);
  if (!parts.length) parts.push(`${num(item.events)} events`);
  return parts.slice(0, 2).join(' / ');
}

const flowPath = (x1: number, y1: number, x2: number, y2: number): string => {
  const mid = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;
};

function summaryText(map: LeakMapReport | null): string {
  if (!map) return 'Waiting for posture data';
  const s = map.summary;
  if (!num(s.events)) return `No sanitized activity yet — the map draws as sensors report flows / ${s.privacy || 'prompt bodies excluded'}`;
  return `${plural(num(s.segments), 'department')} / ${plural(num(s.destinations), 'AI destination')} / ${num(s.uncontrolled)} uncontrolled / ${num(s.shadow)} shadow / ${num(s.controlRate)}% controlled / ${s.privacy || 'prompt bodies excluded'}`;
}

function findSelected(map: LeakMapReport, selected: Selection | null):
  | { kind: 'edge'; item: LeakMapEdge }
  | { kind: string; item: LeakMapNode }
  | null {
  if (selected) {
    if (selected.kind === 'edge') {
      const edge = map.edges.find((item) => item.id === selected.id);
      if (edge) return { kind: 'edge', item: edge };
    } else {
      const [kind, ...rest] = selected.id.split(':');
      const id = rest.join(':');
      const list = kind === 'segment' ? map.segments : kind === 'channel' ? map.channels : map.destinations;
      const node = list.find((item) => item.id === id);
      if (node) return { kind, item: node };
    }
  }
  return map.edges.length ? { kind: 'edge', item: map.edges[0] } : null;
}

function flowsLine(item: LeakMapNode | LeakMapEdge): string {
  const categories = ('categories' in item ? item.categories || [] : [])
    .map((cat) => `${cat.label} ×${num(cat.events)}`)
    .join(', ');
  return categories
    ? `${categories} — masked findings only, never raw values.`
    : `${num(item.sensitive)} sensitive of ${num(item.events)} events — masked findings only, never raw values.`;
}

function outcomeLine(item: LeakMapNode | LeakMapEdge): string {
  const parts: string[] = [];
  if (num(item.blocked)) parts.push(`${num(item.blocked)} stopped at the wall`);
  if (num(item.redacted)) parts.push(`${num(item.redacted)} redacted before the model`);
  if (num(item.pending)) parts.push(`${num(item.pending)} held for approval`);
  if (num(item.coached)) parts.push(`${num(item.coached)} coached`);
  if (num(item.uncontrolled)) parts.push(`${num(item.uncontrolled)} reached the destination uncontrolled`);
  if (num(item.shadow)) parts.push(`${num(item.shadow)} shadow AI sightings`);
  return parts.length ? `${parts.join('; ')}.` : 'No sensitive findings on this path yet.';
}

function exposureLine(item: LeakMapNode | LeakMapEdge): string {
  if (num(item.uncontrolled)) return `${num(item.uncontrolled)} sensitive events left with no control applied.`;
  if (num(item.shadow)) return `${num(item.shadow)} sightings of ungoverned AI on this path.`;
  return 'No uncontrolled egress recorded on this path.';
}

interface NodeBoxProps {
  item: LeakMapNode;
  kind: string;
  x: number;
  y: number;
  kicker: string;
  dim: boolean;
  active: boolean;
  onPick: (id: string) => void;
}

function NodeBox({ item, kind, x, y, kicker, dim, active, onPick }: NodeBoxProps) {
  const id = `${kind}:${item.id}`;
  return (
    <g
      className={`leak-node ${item.status || 'idle'}${dim ? ' is-dim' : ''}${active ? ' is-active' : ''}`}
      data-leak-node={id}
      role="button"
      tabIndex={0}
      aria-label={`${item.label}: ${nodeSub(item)}`}
      onClick={() => onPick(id)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onPick(id);
        }
      }}
    >
      <rect x={x} y={y - NODE_H / 2} width={NODE_W} height={NODE_H} rx={9} />
      <text className="leak-node-kicker" x={x + 12} y={y - 9}>{kicker}</text>
      <text className="leak-node-title" x={x + 12} y={y + 7}>{trim(item.label, 30)}</text>
      <text className="leak-node-sub" x={x + 12} y={y + 21}>{nodeSub(item)}</text>
    </g>
  );
}

export default function LeakMap({ map, surfaces }: { map: LeakMapReport | null; surfaces?: PostureSurface[] }) {
  const [filter, setFilter] = useState<Filter>('all');
  const [category, setCategory] = useState('');
  const [selected, setSelected] = useState<Selection | null>(null);
  const still = useReducedMotion();

  const model = useMemo(() => {
    if (!map || (!map.segments.length && !map.destinations.length)) return null;
    const rows = Math.max(map.segments.length, map.channels.length, map.destinations.length, 3);
    const height = PAD_TOP + PAD_BOT + rows * ROW_H;
    const dests = new Map(map.destinations.map((item) => [item.id, item]));
    const pos = {
      segments: new Map(map.segments.map((item, i) => [item.id, yFor(i, map.segments.length, height)])),
      channels: new Map(map.channels.map((item, i) => [item.id, yFor(i, map.channels.length, height)])),
      destinations: new Map(map.destinations.map((item, i) => [item.id, yFor(i, map.destinations.length, height)])),
    };
    const visible = map.edges.filter((edge) => edgeVisible(edge, filter, category, dests));
    const touched = new Set<string>();
    for (const edge of visible) {
      touched.add(`segment:${edge.from}`);
      touched.add(`channel:${edge.via}`);
      touched.add(`destination:${edge.to}`);
    }
    return { height, dests, pos, visible, touched };
  }, [map, filter, category]);

  const pick = (id: string) => setSelected({ kind: 'node', id });
  const sel = map ? findSelected(map, selected) : null;
  const audit = (surfaces || []).find((surface) => surface.id === 'surface-audit-evidence');

  const inspector = sel && map && (
    <div className="leak-map-inspector" id="leakMapInspector" aria-live="polite">
      <div className="leak-inspector-head">
        <div>
          <h4>
            {sel.kind === 'edge'
              ? `${(sel.item as LeakMapEdge).from.split(':').pop()?.replace(/-/g, ' ')} → ${(sel.item as LeakMapEdge).to}`
              : `${sel.item.label} (${sel.kind === 'segment' ? sel.item.typeLabel || 'segment' : sel.kind === 'channel' ? 'control point' : destKicker(sel.item as LeakMapNode).toLowerCase()})`}
          </h4>
          <p>
            {sel.kind === 'edge'
              ? `Via the ${(sel.item as LeakMapEdge).viaLabel || 'API'} control point / last seen ${sel.item.lastSeen ? new Date(sel.item.lastSeen).toLocaleString() : '—'}`
              : `${num(sel.item.events)} events in the ${sel.kind} / last seen ${sel.item.lastSeen ? new Date(sel.item.lastSeen).toLocaleString() : '—'}`}
          </p>
        </div>
        <div className="leak-inspector-ctas">
          {num(sel.item.pending) > 0 && <a className="leak-cta" href={routeHref('/queue')}>Open approval queue</a>}
          {(num(sel.item.shadow) > 0 || (sel.kind === 'edge' && map.destinations.find((d) => d.id === (sel.item as LeakMapEdge).to)?.state === 'shadow')) && (
            <a className="leak-cta" href="/index.html?tab=coverage">Review shadow AI</a>
          )}
          {(sel.kind === 'edge' ? (sel.item as LeakMapEdge).via : sel.item.id) === 'mcp_guard' && (
            <a className="leak-cta" href="/index.html?tab=policy">Review MCP policy</a>
          )}
          <a className="leak-cta" href={routeHref('/audit')}>Export evidence pack</a>
        </div>
      </div>
      <div className="leak-inspector-grid">
        <div className="leak-inspector-field"><span>What is flowing</span><b>{flowsLine(sel.item)}</b></div>
        <div className="leak-inspector-field"><span>Control outcome</span><b>{outcomeLine(sel.item)}</b></div>
        <div className={`leak-inspector-field${num(sel.item.uncontrolled) || num(sel.item.shadow) ? ' is-alert' : ''}`}>
          <span>Exposure</span><b>{exposureLine(sel.item)}</b>
        </div>
        <div className="leak-inspector-field">
          <span>Proof</span>
          <b>
            {audit && audit.status === 'online'
              ? `Tamper-evident audit chain verified: ${audit.description || 'linked entries verified.'} Sanitized receipts only.`
              : 'Audit chain needs review before this path can be evidenced.'}
          </b>
        </div>
      </div>
    </div>
  );

  return (
    <section className="leak-map-section" aria-label="AI data leak exposure map">
      <div className="leak-map-head">
        <div>
          <h3>AI Data Leak Exposure Map</h3>
          <span id="leakMapSummary">{summaryText(map)}</span>
        </div>
        <div className="leak-map-lens" id="leakMapLens" role="group" aria-label="Exposure filter">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              className={`leak-lens-button${filter === item.id ? ' is-active' : ''}`}
              type="button"
              data-leak-filter={item.id}
              aria-pressed={filter === item.id}
              onClick={() => setFilter(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>
      <div className="leak-map-scenarios" id="leakMapScenarios" aria-label="Data type filters">
        {map && map.categories.length ? (
          map.categories.map((item) => (
            <button
              key={item.label}
              className={`leak-scenario-chip${category === item.label ? ' is-active' : ''}`}
              type="button"
              data-leak-category={item.label}
              aria-pressed={category === item.label}
              onClick={() => setCategory((current) => (current === item.label ? '' : item.label))}
            >
              {trim(item.label, 26)}<b>{num(item.events)}</b>
            </button>
          ))
        ) : (
          <span className="leak-chip-empty">Data types appear as sanitized findings arrive.</span>
        )}
      </div>
      <div className={`leak-map-stage${still ? ' is-static' : ''}`} id="leakMapStage">
        {model && map ? (
          <svg viewBox={`0 0 ${W} ${model.height}`} role="img" aria-label="Map of sensitive data paths from departments through RedactWall to AI destinations">
            <text className="leak-col-label" x={10} y={24}>DEPARTMENTS &amp; TEAMS</text>
            <text className="leak-col-label" x={(CH_L + CH_R) / 2} y={24} textAnchor="middle">REDACTWALL</text>
            <text className="leak-col-label" x={W - 10} y={24} textAnchor="end">AI DESTINATIONS</text>
            <rect className="leak-wall" x={(CH_L + CH_R) / 2 - 23} y={PAD_TOP - 18} width={46} height={model.height - PAD_TOP - PAD_BOT + 30} rx={14} />
            {model.visible.map((edge) => {
              const from = model.pos.segments.get(edge.from);
              const via = model.pos.channels.get(edge.via) ?? [...model.pos.channels.values()][0];
              const to = model.pos.destinations.get(edge.to);
              if (from === undefined || via === undefined || to === undefined) return null;
              const tone = edgeTone(edge, model.dests);
              const width = edgeWidth(edge);
              const escapes = num(edge.uncontrolled) > 0 || num(edge.shadow) > 0
                || num(edge.events) > num(edge.blocked) + num(edge.coached);
              const flow = still ? '' : ' leak-flow';
              const onPick = () => setSelected({ kind: 'edge', id: edge.id });
              return (
                <g className={`leak-edge ${tone}`} data-leak-edge={edge.id} key={edge.id} onClick={onPick}>
                  <path className={`leak-line${flow}`} d={flowPath(SEG_X, from, CH_L, via)} strokeWidth={width} />
                  {escapes
                    ? <path className={`leak-line${flow}`} d={flowPath(CH_R, via, DEST_X, to)} strokeWidth={width} />
                    : <circle className="leak-stop" cx={CH_R + 10} cy={via} r={5} />}
                  <path className="leak-hit" d={flowPath(SEG_X, from, CH_L, via)} />
                  {escapes && <path className="leak-hit" d={flowPath(CH_R, via, DEST_X, to)} />}
                  <title>{`${edge.from.split(':').pop()} -> ${edge.to}: ${nodeSub(edge)}`}</title>
                </g>
              );
            })}
            {map.segments.map((item) => (
              <NodeBox
                key={item.id}
                item={item}
                kind="segment"
                x={10}
                y={model.pos.segments.get(item.id) ?? PAD_TOP}
                kicker={`${item.typeLabel || 'Segment'}${num(item.users) ? ` · ${plural(num(item.users), 'user')}` : ''}`}
                dim={model.visible.length > 0 && !model.touched.has(`segment:${item.id}`)}
                active={selected?.kind === 'node' && selected.id === `segment:${item.id}`}
                onPick={pick}
              />
            ))}
            {map.channels.map((item) => {
              const y = model.pos.channels.get(item.id) ?? PAD_TOP;
              const x = (CH_L + CH_R) / 2 - CH_W / 2;
              const id = `channel:${item.id}`;
              return (
                <g
                  key={item.id}
                  className={`leak-node leak-channel ${item.status || 'idle'}${selected?.kind === 'node' && selected.id === id ? ' is-active' : ''}`}
                  data-leak-node={id}
                  role="button"
                  tabIndex={0}
                  aria-label={`${item.label} control point: ${nodeSub(item)}`}
                  onClick={() => pick(id)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      pick(id);
                    }
                  }}
                >
                  <rect x={x} y={y - CH_H / 2} width={CH_W} height={CH_H} rx={9} />
                  <text className="leak-node-title" x={x + CH_W / 2} y={y - 3} textAnchor="middle">{trim(item.label, 14)}</text>
                  <text className="leak-node-sub" x={x + CH_W / 2} y={y + 13} textAnchor="middle">{nodeSub(item)}</text>
                </g>
              );
            })}
            {map.destinations.map((item) => (
              <NodeBox
                key={item.id}
                item={item}
                kind="destination"
                x={DEST_X}
                y={model.pos.destinations.get(item.id) ?? PAD_TOP}
                kicker={destKicker(item)}
                dim={model.visible.length > 0 && !model.touched.has(`destination:${item.id}`)}
                active={selected?.kind === 'node' && selected.id === `destination:${item.id}`}
                onPick={pick}
              />
            ))}
          </svg>
        ) : (
          <div className="leak-map-empty">
            <b>No paths mapped yet</b>
            <p>Connect sensors and the exposure map draws every department-to-AI flow from sanitized events.</p>
          </div>
        )}
      </div>
      {inspector}
    </section>
  );
}
