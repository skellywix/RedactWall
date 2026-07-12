import { useEffect, useMemo, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import type {
  LeakMapEdge,
  LeakMapNode,
  LeakMapReport,
  PostureSurface,
} from '../../api/posture';
import { routeHref } from '../../lib/router';
import { continuedEventCount } from './leakMapTraffic';
import './LeakMap.css';

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
const MIN_ZOOM = 1;
const MAX_ZOOM = 1.8;
const ZOOM_STEP = 0.2;
const PAN_STEP = 64;

type Filter = 'all' | 'risk' | 'shadow';
type ViewMode = 'map' | 'details';
export type LeakMapDataState = 'loading' | 'unavailable' | 'empty' | 'populated';
type NodeKind = 'segment' | 'channel' | 'destination';
type Selection = { kind: 'edge'; id: string } | { kind: 'node'; id: string };
type ResolvedSelection =
  | { kind: 'edge'; item: LeakMapEdge }
  | { kind: NodeKind; item: LeakMapNode };

interface Viewport {
  zoom: number;
  x: number;
  y: number;
}

interface MapModel {
  height: number;
  lookups: {
    segments: Map<string, LeakMapNode>;
    channels: Map<string, LeakMapNode>;
    destinations: Map<string, LeakMapNode>;
  };
  pos: {
    segments: Map<string, number>;
    channels: Map<string, number>;
    destinations: Map<string, number>;
  };
  visible: LeakMapEdge[];
  touched: Set<string>;
}

interface RelationLabels {
  from: string;
  via: string;
  to: string;
}

const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'All FCU flows' },
  { id: 'risk', label: 'At-risk' },
  { id: 'shadow', label: 'Shadow AI' },
];

const LEGEND = [
  { className: 'is-clean', label: 'Governed', detail: 'controlled path' },
  { className: 'is-held', label: 'Held', detail: 'review or justification' },
  { className: 'is-leak', label: 'Uncontrolled', detail: 'observation recorded' },
  { className: 'is-shadow', label: 'Shadow AI', detail: 'ungoverned destination' },
  { className: 'is-stop', label: 'No continuation', detail: 'held, blocked, or observational' },
];

const EMPTY_VIEWPORT: Viewport = { zoom: 1, x: 0, y: 0 };
const MASKED_LABEL = '[masked label]';
const SSN_SHAPE = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g;
const CARD_SHAPE = /\b(?:\d[ -]?){13,19}\b/g;
const EMAIL_SHAPE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const SECRET_SHAPE = /\b(?:sk|rk)-[A-Z0-9_-]{12,}\b/gi;

const num = (value: unknown): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : 0;
};

const trim = (value: string, max: number): string =>
  value.length > max ? `${value.slice(0, max - 1)}…` : value;

const plural = (count: number, word: string): string =>
  `${count} ${word}${count === 1 ? '' : 's'}`;

/** Defense in depth for the already-sanitized labels in posture.leakMap. */
function sanitizedLabel(value: unknown, fallback: string, max = 72): string {
  const normalized = String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!normalized) return fallback;
  const masked = normalized
    .replace(SSN_SHAPE, MASKED_LABEL)
    .replace(CARD_SHAPE, MASKED_LABEL)
    .replace(EMAIL_SHAPE, MASKED_LABEL)
    .replace(SECRET_SHAPE, MASKED_LABEL);
  return trim(masked, max);
}

function mediaMatches(query: string): boolean {
  try {
    return window.matchMedia(query).matches;
  } catch {
    return false;
  }
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => mediaMatches(query));
  useEffect(() => {
    const media = window.matchMedia(query);
    const onChange = () => setMatches(media.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

function edgeVisible(edge: LeakMapEdge, filter: Filter, category: string, destinations: Map<string, LeakMapNode>): boolean {
  if (filter === 'risk' && !(num(edge.uncontrolled) || num(edge.shadow) || num(edge.pending))) return false;
  if (filter === 'shadow' && !(num(edge.shadow) || destinations.get(edge.to)?.state === 'shadow')) return false;
  return !category || (edge.categories || []).some((item) => item.label === category);
}

function edgeTone(edge: LeakMapEdge, destinations: Map<string, LeakMapNode>): string {
  if (num(edge.shadow) || destinations.get(edge.to)?.state === 'shadow') return 'is-shadow';
  if (num(edge.uncontrolled)) return 'is-leak';
  if (num(edge.pending)) return 'is-held';
  return 'is-clean';
}

function outboundTone(edge: LeakMapEdge): string {
  return num(edge.uncontrolledContinued) ? 'is-leak' : 'is-clean';
}

function edgeStateLabel(edge: LeakMapEdge, destinations: Map<string, LeakMapNode>): string {
  const tone = edgeTone(edge, destinations);
  const continued = continuedEventCount(edge);
  if (!continued && tone === 'is-shadow') return 'Shadow AI observation / continuation not confirmed';
  if (!continued && tone === 'is-leak') return 'Uncontrolled observation / continuation not confirmed';
  if (tone === 'is-held') return continued ? 'Held + policy-authorized continuation' : 'Held for review or justification';
  if (!continued && num(edge.blocked)) return 'Stopped at RedactWall';
  if (!continued && num(edge.coached)) return 'Coaching recorded / continuation not confirmed';
  if (!continued) return 'Observed / continuation not confirmed';
  if (num(edge.redacted) === continued) return 'Redacted for safe continuation';
  return num(edge.uncontrolledContinued)
    ? 'Includes policy-authorized sensitive continuation / delivery not confirmed'
    : 'Policy-authorized continuation / delivery not confirmed';
}

const trafficWidth = (events: number): number =>
  Number((1.6 + Math.min(4.4, Math.log2(num(events) + 1))).toFixed(1));

const yFor = (index: number, count: number, height: number): number =>
  PAD_TOP + (height - PAD_TOP - PAD_BOT) * ((index + 0.5) / Math.max(1, count));

function destKicker(destination: LeakMapNode): string {
  const state = String(destination.state || 'observed');
  if (state === 'sanctioned') return 'GOVERNED';
  if (state === 'shadow') return 'SHADOW AI';
  if (state === 'unsanctioned') return 'UNSANCTIONED';
  return sanitizedLabel(state, 'OBSERVED', 20).toUpperCase();
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

function summaryText(map: LeakMapReport | null, state: LeakMapDataState): string {
  if (state === 'loading') return 'Loading sanitized posture evidence';
  if (state === 'unavailable') return map
    ? 'Live posture unavailable / last verified snapshot retained'
    : 'Live posture unavailable / no empty-state conclusion made';
  if (!map) return 'Waiting for posture data';
  const summary = map.summary;
  const privacy = sanitizedLabel(summary.privacy, 'prompt bodies excluded', 48);
  if (!num(summary.events)) return `No sanitized member-data activity yet / ${privacy}`;
  return `${plural(num(summary.segments), 'team')} / ${plural(num(summary.destinations), 'AI destination')} / ${num(summary.uncontrolled)} uncontrolled / ${num(summary.shadow)} shadow / ${num(summary.controlRate)}% controlled / ${privacy}`;
}

function buildModel(map: LeakMapReport | null, filter: Filter, category: string): MapModel | null {
  if (!map || (!map.segments.length && !map.destinations.length)) return null;
  const rows = Math.max(map.segments.length, map.channels.length, map.destinations.length, 3);
  const height = PAD_TOP + PAD_BOT + rows * ROW_H;
  const lookups = {
    segments: new Map(map.segments.map((item) => [item.id, item])),
    channels: new Map(map.channels.map((item) => [item.id, item])),
    destinations: new Map(map.destinations.map((item) => [item.id, item])),
  };
  const pos = {
    segments: new Map(map.segments.map((item, index) => [item.id, yFor(index, map.segments.length, height)])),
    channels: new Map(map.channels.map((item, index) => [item.id, yFor(index, map.channels.length, height)])),
    destinations: new Map(map.destinations.map((item, index) => [item.id, yFor(index, map.destinations.length, height)])),
  };
  const visible = map.edges.filter((edge) => edgeVisible(edge, filter, category, lookups.destinations));
  const touched = new Set<string>();
  visible.forEach((edge) => {
    touched.add(`segment:${edge.from}`);
    touched.add(`channel:${edge.via}`);
    touched.add(`destination:${edge.to}`);
  });
  return { height, lookups, pos, visible, touched };
}

function relationshipLabels(edge: LeakMapEdge, model: MapModel): RelationLabels {
  return {
    from: sanitizedLabel(model.lookups.segments.get(edge.from)?.label, 'Unassigned team'),
    via: sanitizedLabel(model.lookups.channels.get(edge.via)?.label || edge.viaLabel, 'API control'),
    to: sanitizedLabel(model.lookups.destinations.get(edge.to)?.label, 'Unknown destination'),
  };
}

function findSelected(map: LeakMapReport, selected: Selection | null, fallbackEdges: LeakMapEdge[]): ResolvedSelection | null {
  if (selected?.kind === 'edge') {
    const edge = map.edges.find((item) => item.id === selected.id);
    if (edge) return { kind: 'edge', item: edge };
  }
  if (selected?.kind === 'node') {
    const separator = selected.id.indexOf(':');
    const kind = selected.id.slice(0, separator) as NodeKind;
    const id = selected.id.slice(separator + 1);
    const nodes = kind === 'segment' ? map.segments : kind === 'channel' ? map.channels : map.destinations;
    const node = nodes.find((item) => item.id === id);
    if (node) return { kind, item: node };
  }
  // A filter with zero matches must not silently inspect an unrelated path.
  // Explicit selections remain available above and carry the outside-filter
  // notice; an implicit fallback is limited to the visible relationship set.
  const edge = fallbackEdges[0];
  return edge ? { kind: 'edge', item: edge } : null;
}

function selectionState(selection: ResolvedSelection | null): Selection | null {
  if (!selection) return null;
  return selection.kind === 'edge'
    ? { kind: 'edge', id: selection.item.id }
    : { kind: 'node', id: `${selection.kind}:${selection.item.id}` };
}

function flowsLine(item: LeakMapNode | LeakMapEdge): string {
  const categories = ('categories' in item ? item.categories || [] : [])
    .map((category) => `${sanitizedLabel(category.label, 'Classified data', 32)} ×${num(category.events)}`)
    .join(', ');
  return categories
    ? `${categories} - masked findings only, never source values.`
    : `${num(item.sensitive)} sensitive of ${num(item.events)} events - masked findings only, never source values.`;
}

function outcomeLine(item: LeakMapNode | LeakMapEdge): string {
  const parts: string[] = [];
  if (num(item.blocked)) parts.push(`${num(item.blocked)} stopped at the wall`);
  if (num(item.redacted)) parts.push(`${num(item.redacted)} redacted before the model`);
  if (num(item.pending)) parts.push(`${num(item.pending)} held for review or justification`);
  if (num(item.coached)) parts.push(`${num(item.coached)} coached`);
  if (num(item.uncontrolled)) parts.push(`${num(item.uncontrolled)} uncontrolled observations; continuation relationship not inferred`);
  if (continuedEventCount(item)) parts.push(`${plural(continuedEventCount(item), 'policy-authorized continuation decision')}; delivery not confirmed`);
  if (num(item.shadow)) parts.push(`${num(item.shadow)} shadow AI sightings`);
  return parts.length ? `${parts.join('; ')}.` : 'No sensitive findings on this path yet.';
}

function exposureLine(item: LeakMapNode | LeakMapEdge): string {
  if (num(item.uncontrolled)) return `${num(item.uncontrolled)} uncontrolled observations; continuation relationship not inferred.`;
  if (num(item.shadow)) return `${num(item.shadow)} sightings of ungoverned AI on this path.`;
  return 'No uncontrolled observation recorded on this path.';
}

function formatDate(value?: string | null): string {
  if (!value) return 'Not yet observed';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
}

function activateOnKey(event: ReactKeyboardEvent<SVGGElement>, onPick: () => void) {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  onPick();
}

function nodeStatusClass(status: string): string {
  return ['online', 'warning', 'error', 'idle'].includes(status) ? status : 'idle';
}

interface NodeBoxProps {
  item: LeakMapNode;
  kind: 'segment' | 'destination';
  x: number;
  y: number;
  kicker: string;
  dim: boolean;
  active: boolean;
  onPick: (id: string) => void;
}

function NodeBox({ item, kind, x, y, kicker, dim, active, onPick }: NodeBoxProps) {
  const id = `${kind}:${item.id}`;
  const label = sanitizedLabel(item.label, kind === 'segment' ? 'Unassigned team' : 'Unknown destination');
  const select = () => onPick(id);
  return (
    <g
      className={`leak-node ${nodeStatusClass(item.status)}${dim ? ' is-dim' : ''}${active ? ' is-active' : ''}`}
      data-leak-node={id}
      role="button"
      tabIndex={0}
      aria-label={`${label}: ${nodeSub(item)}`}
      aria-pressed={active}
      onClick={select}
      onKeyDown={(event) => activateOnKey(event, select)}
    >
      <rect x={x} y={y - NODE_H / 2} width={NODE_W} height={NODE_H} rx={9} />
      <text className="leak-node-kicker" x={x + 12} y={y - 9}>{sanitizedLabel(kicker, 'OBSERVED', 34)}</text>
      <text className="leak-node-title" x={x + 12} y={y + 7}>{trim(label, 30)}</text>
      <text className="leak-node-sub" x={x + 12} y={y + 21}>{nodeSub(item)}</text>
    </g>
  );
}

function ChannelNode({ item, y, active, onPick }: { item: LeakMapNode; y: number; active: boolean; onPick: (id: string) => void }) {
  const x = (CH_L + CH_R) / 2 - CH_W / 2;
  const id = `channel:${item.id}`;
  const label = sanitizedLabel(item.label, 'API control');
  const select = () => onPick(id);
  return (
    <g
      className={`leak-node leak-channel ${nodeStatusClass(item.status)}${active ? ' is-active' : ''}`}
      data-leak-node={id}
      role="button"
      tabIndex={0}
      aria-label={`${label} control point: ${nodeSub(item)}`}
      aria-pressed={active}
      onClick={select}
      onKeyDown={(event) => activateOnKey(event, select)}
    >
      <rect x={x} y={y - CH_H / 2} width={CH_W} height={CH_H} rx={9} />
      <text className="leak-node-title" x={x + CH_W / 2} y={y - 3} textAnchor="middle">{trim(label, 14)}</text>
      <text className="leak-node-sub" x={x + CH_W / 2} y={y + 13} textAnchor="middle">{nodeSub(item)}</text>
    </g>
  );
}

function MapEdge({ edge, model, selected, still, onPick }: { edge: LeakMapEdge; model: MapModel; selected: boolean; still: boolean; onPick: () => void }) {
  const from = model.pos.segments.get(edge.from);
  const via = model.pos.channels.get(edge.via) ?? [...model.pos.channels.values()][0];
  const to = model.pos.destinations.get(edge.to);
  if (from === undefined || via === undefined || to === undefined) return null;
  const labels = relationshipLabels(edge, model);
  const tone = edgeTone(edge, model.lookups.destinations);
  const destinationTone = outboundTone(edge);
  const state = edgeStateLabel(edge, model.lookups.destinations);
  const continued = continuedEventCount(edge);
  const continues = continued > 0;
  const flow = still ? '' : ' leak-flow';
  const label = `${labels.from} to ${labels.to} through ${labels.via}: ${state}; ${nodeSub(edge)}`;
  return (
    <g
      className={`leak-edge ${tone}${selected ? ' is-active' : ''}`}
      data-leak-edge={edge.id}
      data-continuation-events={continued}
      role="button"
      tabIndex={0}
      aria-label={label}
      aria-pressed={selected}
      onClick={onPick}
      onKeyDown={(event) => activateOnKey(event, onPick)}
    >
      <path aria-hidden="true" data-leak-leg="ingress" className={`leak-line ${tone}${flow}`} d={flowPath(SEG_X, from, CH_L, via)} strokeWidth={trafficWidth(num(edge.events))} />
      {continues
        ? <path aria-hidden="true" data-leak-leg="outbound" className={`leak-line ${destinationTone}${flow}`} d={flowPath(CH_R, via, DEST_X, to)} strokeWidth={trafficWidth(continued)} />
        : <circle aria-hidden="true" className="leak-stop" cx={CH_R + 10} cy={via} r={5} />}
      <path aria-hidden="true" className="leak-hit" d={flowPath(SEG_X, from, CH_L, via)} />
      {continues && <path aria-hidden="true" className="leak-hit" d={flowPath(CH_R, via, DEST_X, to)} />}
      <title>{label}</title>
    </g>
  );
}

function viewportTransform(viewport: Viewport, height: number): string {
  const centerX = W / 2;
  const centerY = height / 2;
  return `translate(${centerX + viewport.x} ${centerY + viewport.y}) scale(${viewport.zoom}) translate(${-centerX} ${-centerY})`;
}

function GraphView({ map, model, selected, still, viewport, onPickNode, onPickEdge }: {
  map: LeakMapReport;
  model: MapModel;
  selected: Selection | null;
  still: boolean;
  viewport: Viewport;
  onPickNode: (id: string) => void;
  onPickEdge: (id: string) => void;
}) {
  return (
    <div className={`leak-map-stage${still ? ' is-static' : ''}`} id="leakMapStage">
      <p className="leak-map-stage-note" id="leakMapStageNote">
        Showing {model.visible.length} of {map.edges.length} sanitized relationships. Outbound legs represent a recorded policy-authorized continuation, not delivery confirmation. Held, blocked, coached-only, and observational events have no outbound leg. Tab to select a path or node.
      </p>
      <svg viewBox={`0 0 ${W} ${model.height}`} role="group" aria-label="Map of member-data paths from Texas FCU teams through RedactWall to AI destinations" aria-describedby="leakMapStageNote">
        <g className="leak-map-viewport" transform={viewportTransform(viewport, model.height)}>
          <text aria-hidden="true" className="leak-col-label" x={10} y={24}>TEXAS FCU TEAMS</text>
          <text aria-hidden="true" className="leak-col-label" x={(CH_L + CH_R) / 2} y={24} textAnchor="middle">REDACTWALL</text>
          <text aria-hidden="true" className="leak-col-label" x={W - 10} y={24} textAnchor="end">AI DESTINATIONS</text>
          <rect aria-hidden="true" className="leak-wall" x={(CH_L + CH_R) / 2 - 23} y={PAD_TOP - 18} width={46} height={model.height - PAD_TOP - PAD_BOT + 30} rx={14} />
          {model.visible.map((edge) => (
            <MapEdge
              key={edge.id}
              edge={edge}
              model={model}
              selected={selected?.kind === 'edge' && selected.id === edge.id}
              still={still}
              onPick={() => onPickEdge(edge.id)}
            />
          ))}
          {map.segments.map((item) => (
            <NodeBox
              key={item.id}
              item={item}
              kind="segment"
              x={10}
              y={model.pos.segments.get(item.id) ?? PAD_TOP}
              kicker={`${sanitizedLabel(item.typeLabel, 'Segment', 20)}${num(item.users) ? ` · ${plural(num(item.users), 'user')}` : ''}`}
              dim={model.visible.length > 0 && !model.touched.has(`segment:${item.id}`)}
              active={selected?.kind === 'node' && selected.id === `segment:${item.id}`}
              onPick={onPickNode}
            />
          ))}
          {map.channels.map((item) => (
            <ChannelNode
              key={item.id}
              item={item}
              y={model.pos.channels.get(item.id) ?? PAD_TOP}
              active={selected?.kind === 'node' && selected.id === `channel:${item.id}`}
              onPick={onPickNode}
            />
          ))}
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
              onPick={onPickNode}
            />
          ))}
        </g>
      </svg>
    </div>
  );
}

function MapLegend() {
  return (
    <ul className="leak-map-legend" aria-label="Exposure map legend">
      {LEGEND.map((item) => (
        <li key={item.label}>
          <span aria-hidden="true" className={`leak-legend-mark ${item.className}`} />
          <span><b>{item.label}</b><small>{item.detail}</small></span>
        </li>
      ))}
    </ul>
  );
}

function MapHeader({ map, state, mode, onMode, interactive }: { map: LeakMapReport | null; state: LeakMapDataState; mode: ViewMode; onMode: (mode: ViewMode) => void; interactive: boolean }) {
  return (
    <div className="leak-map-head">
      <div className="leak-map-title">
        <span className="leak-map-eyebrow">Sanitized path evidence</span>
        <h3>Texas FCU AI Exposure Map</h3>
        <span id="leakMapSummary">{summaryText(map, state)}</span>
      </div>
      {interactive && (
        <div className="leak-map-view-switch" role="group" aria-label="Exposure map view">
          <button type="button" data-map-view="map" aria-pressed={mode === 'map'} onClick={() => onMode('map')}>Map</button>
          <button type="button" data-map-view="details" aria-pressed={mode === 'details'} onClick={() => onMode('details')}>Details</button>
        </div>
      )}
    </div>
  );
}

function FilterBar({ map, filter, category, onFilter, onCategory }: {
  map: LeakMapReport | null;
  filter: Filter;
  category: string;
  onFilter: (filter: Filter) => void;
  onCategory: (category: string) => void;
}) {
  return (
    <div className="leak-map-filters">
      <div className="leak-map-lens" id="leakMapLens" role="group" aria-label="Exposure filter">
        {FILTERS.map((item) => (
          <button key={item.id} type="button" data-leak-filter={item.id} aria-pressed={filter === item.id} onClick={() => onFilter(item.id)}>
            {item.label}
          </button>
        ))}
      </div>
      <div className="leak-map-scenarios" id="leakMapScenarios" role="group" aria-label="Data type filters">
        {map?.categories.length ? map.categories.map((item) => (
          <button
            key={item.label}
            className="leak-scenario-chip"
            type="button"
            data-leak-category={item.label}
            aria-pressed={category === item.label}
            onClick={() => onCategory(category === item.label ? '' : item.label)}
          >
            {sanitizedLabel(item.label, 'Classified data', 26)}<b>{num(item.events)}</b>
          </button>
        )) : <span className="leak-chip-empty">Data types appear as sanitized findings arrive.</span>}
      </div>
    </div>
  );
}

function MapToolbar({ viewport, reduced, paused, onZoom, onPan, onFit, onReset, onPause }: {
  viewport: Viewport;
  reduced: boolean;
  paused: boolean;
  onZoom: (delta: number) => void;
  onPan: (x: number, y: number) => void;
  onFit: () => void;
  onReset: () => void;
  onPause: () => void;
}) {
  const canPan = viewport.zoom > MIN_ZOOM;
  return (
    <div className="leak-map-toolbar" role="toolbar" aria-label="Map navigation and motion controls">
      <div className="leak-control-group" role="group" aria-label="Zoom controls">
        <button type="button" data-map-control="zoom-out" disabled={viewport.zoom <= MIN_ZOOM} onClick={() => onZoom(-ZOOM_STEP)}>Zoom out</button>
        <output aria-label="Map zoom">{Math.round(viewport.zoom * 100)}%</output>
        <button type="button" data-map-control="zoom-in" disabled={viewport.zoom >= MAX_ZOOM} onClick={() => onZoom(ZOOM_STEP)}>Zoom in</button>
      </div>
      <div className="leak-control-group leak-pan-controls" role="group" aria-label="Pan controls">
        <span>Pan</span>
        <button type="button" aria-label="Pan map left" title="Pan map left" disabled={!canPan} onClick={() => onPan(PAN_STEP, 0)}>←</button>
        <button type="button" aria-label="Pan map up" title="Pan map up" disabled={!canPan} onClick={() => onPan(0, PAN_STEP)}>↑</button>
        <button type="button" aria-label="Pan map down" title="Pan map down" disabled={!canPan} onClick={() => onPan(0, -PAN_STEP)}>↓</button>
        <button type="button" aria-label="Pan map right" title="Pan map right" disabled={!canPan} onClick={() => onPan(-PAN_STEP, 0)}>→</button>
      </div>
      <div className="leak-control-group leak-view-controls">
        <button type="button" data-map-control="fit" onClick={onFit}>Fit</button>
        <button type="button" data-map-control="reset" onClick={onReset}>Reset</button>
        <button type="button" data-map-control="pause" aria-pressed={reduced || paused} disabled={reduced} onClick={onPause}>
          {reduced ? 'Motion reduced' : paused ? 'Resume flow' : 'Pause flow'}
        </button>
      </div>
    </div>
  );
}

function categoryLine(edge: LeakMapEdge): string {
  const labels = (edge.categories || []).map((category) => sanitizedLabel(category.label, 'Classified data', 32));
  return labels.length ? labels.join(', ') : 'No classified data types';
}

function DetailsView({ map, model, selected, onPick }: { map: LeakMapReport; model: MapModel; selected: Selection | null; onPick: (id: string) => void }) {
  return (
    <section className="leak-map-details" id="leakMapDetails" aria-labelledby="leakMapDetailsTitle">
      <div className="leak-details-head">
        <div><h4 id="leakMapDetailsTitle">Sanitized relationships</h4><p>Same evidence as the map, in a reflowable list.</p></div>
        <b>{model.visible.length} / {map.edges.length}</b>
      </div>
      {model.visible.length ? (
        <ul className="leak-relationship-list">
          {model.visible.map((edge) => {
            const labels = relationshipLabels(edge, model);
            const active = selected?.kind === 'edge' && selected.id === edge.id;
            return (
              <li className={active ? 'is-active' : ''} key={edge.id}>
                <div className="leak-relationship-head">
                  <button type="button" aria-pressed={active} onClick={() => onPick(edge.id)}>{labels.from} <span aria-hidden="true">→</span> {labels.to}</button>
                  <span className={`leak-state-badge ${edgeTone(edge, model.lookups.destinations)}`}>{edgeStateLabel(edge, model.lookups.destinations)}</span>
                </div>
                <dl>
                  <div><dt>Control</dt><dd>{labels.via}</dd></div>
                  <div><dt>Traffic</dt><dd>{num(edge.events)} observed / {continuedEventCount(edge)} authorized to continue</dd></div>
                  <div><dt>Data types</dt><dd>{categoryLine(edge)}</dd></div>
                  <div><dt>Last seen</dt><dd>{formatDate(edge.lastSeen)}</dd></div>
                </dl>
              </li>
            );
          })}
        </ul>
      ) : (
        <div className="leak-map-empty" role="status"><b>No matching relationships</b><p>Clear a data type or exposure filter to restore the full sanitized path list.</p></div>
      )}
    </section>
  );
}

function selectionTitle(selection: ResolvedSelection, model: MapModel): string {
  if (selection.kind === 'edge') {
    const labels = relationshipLabels(selection.item, model);
    return `${labels.from} → ${labels.to}`;
  }
  const kind = selection.kind === 'segment'
    ? sanitizedLabel(selection.item.typeLabel, 'segment', 24)
    : selection.kind === 'channel' ? 'control point' : destKicker(selection.item).toLowerCase();
  return `${sanitizedLabel(selection.item.label, 'Sanitized node')} (${kind})`;
}

function selectionMeta(selection: ResolvedSelection, model: MapModel): string {
  if (selection.kind === 'edge') {
    const labels = relationshipLabels(selection.item, model);
    return `Via ${labels.via} / last seen ${formatDate(selection.item.lastSeen)}`;
  }
  return `${num(selection.item.events)} events in the ${selection.kind} / last seen ${formatDate(selection.item.lastSeen)}`;
}

function InspectorActions({ selection, map }: { selection: ResolvedSelection; map: LeakMapReport }) {
  const item = selection.item;
  const shadowDestination = selection.kind === 'edge'
    && map.destinations.find((destination) => destination.id === selection.item.to)?.state === 'shadow';
  const shadow = num(item.shadow) > 0 || shadowDestination;
  const channel = selection.kind === 'edge' ? selection.item.via : selection.item.id;
  return (
    <div className="leak-inspector-ctas">
      {num(item.pending) > 0 && <a className="leak-cta" href={routeHref('/queue')}>Open approval queue</a>}
      {shadow && <a className="leak-cta" href={routeHref('/coverage')}>Review shadow AI</a>}
      {channel === 'mcp_guard' && <a className="leak-cta" href={routeHref('/policy')}>Review MCP policy</a>}
      <a className="leak-cta" href={routeHref('/audit')}>Open audit evidence</a>
    </div>
  );
}

function Inspector({ selection, map, model, audit, outsideFilter }: {
  selection: ResolvedSelection | null;
  map: LeakMapReport;
  model: MapModel;
  audit?: PostureSurface;
  outsideFilter: boolean;
}) {
  if (!selection) return null;
  const proof = audit?.status === 'online'
    ? `Tamper-evident audit chain verified: ${sanitizedLabel(audit.description, 'linked entries verified', 120)}. Sanitized receipts only.`
    : 'Audit chain needs review before this path can be evidenced.';
  return (
    <div className="leak-map-inspector" id="leakMapInspector" aria-live="polite">
      <div className="leak-inspector-head">
        <div>
          <span className="leak-inspector-kicker">Selected evidence</span>
          <h4>{selectionTitle(selection, model)}</h4>
          <p>{selectionMeta(selection, model)}</p>
          {outsideFilter && <span className="leak-selection-note">Selection retained outside the current filter.</span>}
        </div>
        <InspectorActions selection={selection} map={map} />
      </div>
      <div className="leak-inspector-grid">
        <div className="leak-inspector-field"><span>What is flowing</span><b>{flowsLine(selection.item)}</b></div>
        <div className="leak-inspector-field"><span>Control outcome</span><b>{outcomeLine(selection.item)}</b></div>
        <div className={`leak-inspector-field${num(selection.item.uncontrolled) || num(selection.item.shadow) ? ' is-alert' : ''}`}>
          <span>Exposure</span><b>{exposureLine(selection.item)}</b>
        </div>
        <div className="leak-inspector-field"><span>Proof</span><b>{proof}</b></div>
      </div>
    </div>
  );
}

function boundedViewport(viewport: Viewport, height: number): Viewport {
  const zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Number(viewport.zoom.toFixed(1))));
  const maxX = W * (zoom - 1) / 2;
  const maxY = height * (zoom - 1) / 2;
  return {
    zoom,
    x: Math.min(maxX, Math.max(-maxX, viewport.x)),
    y: Math.min(maxY, Math.max(-maxY, viewport.y)),
  };
}

function MapDataNotice({ state, hasSnapshot, onRetry }: { state: LeakMapDataState; hasSnapshot: boolean; onRetry?: () => void }) {
  if (state === 'populated') return null;
  if (state === 'loading') {
    return <div className="leak-map-state is-loading" role="status"><b>Loading exposure evidence</b><p>Waiting for the authenticated posture response.</p></div>;
  }
  if (state === 'unavailable') {
    return (
      <div className="leak-map-state is-unavailable" role="alert">
        <div>
          <b>Exposure evidence unavailable</b>
          <p>{hasSnapshot ? 'The live refresh failed. The last verified snapshot remains visible below.' : 'The posture request failed, so RedactWall did not report an empty graph.'}</p>
        </div>
        {onRetry && <button type="button" onClick={onRetry}>Retry posture</button>}
      </div>
    );
  }
  return <div className="leak-map-state is-empty" role="status"><b>No exposure paths in the verified snapshot</b><p>The posture service responded successfully with zero sanitized team-to-AI relationships.</p></div>;
}

export default function LeakMap({ map, state, surfaces, onRetry }: { map: LeakMapReport | null; state: LeakMapDataState; surfaces?: PostureSurface[]; onRetry?: () => void }) {
  const [filter, setFilter] = useState<Filter>('all');
  const [category, setCategory] = useState('');
  const [selected, setSelected] = useState<Selection | null>(null);
  const [showImplicitSelection, setShowImplicitSelection] = useState(true);
  const [mode, setMode] = useState<ViewMode>(() => mediaMatches('(max-width: 720px)') ? 'details' : 'map');
  const [viewport, setViewport] = useState<Viewport>(EMPTY_VIEWPORT);
  const [paused, setPaused] = useState(false);
  const reduced = useMediaQuery('(prefers-reduced-motion: reduce)');
  const still = reduced || paused;
  const model = useMemo(() => buildModel(map, filter, category), [map, filter, category]);
  const modelHeight = model?.height ?? 0;
  const hasSnapshot = !!map && !!model;
  const canExplore = state === 'populated' || (state === 'unavailable' && hasSnapshot);

  useEffect(() => {
    if (modelHeight) setViewport((current) => boundedViewport(current, modelHeight));
  }, [modelHeight]);

  const selectNode = (id: string) => {
    setShowImplicitSelection(true);
    setSelected({ kind: 'node', id });
  };
  const selectEdge = (id: string) => {
    setShowImplicitSelection(true);
    setSelected({ kind: 'edge', id });
  };
  const fallbackEdges = showImplicitSelection ? model?.visible || [] : [];
  const selection = map ? findSelected(map, selected, fallbackEdges) : null;
  const activeSelection = selectionState(selection);
  const audit = (surfaces || []).find((surface) => surface.id === 'surface-audit-evidence');
  const outsideFilter = selected?.kind === 'edge' && !!model && !model.visible.some((edge) => edge.id === selected.id);
  const updateViewport = (next: (current: Viewport) => Viewport) => {
    if (model) setViewport((current) => boundedViewport(next(current), model.height));
  };
  const reset = () => {
    setFilter('all');
    setCategory('');
    setSelected(null);
    setShowImplicitSelection(false);
    setViewport(EMPTY_VIEWPORT);
  };

  return (
    <section className="leak-map-section" aria-label="AI data leak exposure map" aria-busy={state === 'loading'} data-map-state={state}>
      <MapHeader map={map} state={state} mode={mode} onMode={setMode} interactive={canExplore} />
      <MapDataNotice state={state} hasSnapshot={hasSnapshot} onRetry={onRetry} />
      {canExplore && <FilterBar map={map} filter={filter} category={category} onFilter={setFilter} onCategory={setCategory} />}
      {canExplore && <MapLegend />}
      {canExplore && mode === 'map' && model && map && (
        <>
          <MapToolbar
            viewport={viewport}
            reduced={reduced}
            paused={paused}
            onZoom={(delta) => updateViewport((current) => ({ ...current, zoom: current.zoom + delta }))}
            onPan={(x, y) => updateViewport((current) => ({ ...current, x: current.x + x, y: current.y + y }))}
            onFit={() => setViewport(EMPTY_VIEWPORT)}
            onReset={reset}
            onPause={() => setPaused((current) => !current)}
          />
          <GraphView map={map} model={model} selected={activeSelection} still={still} viewport={viewport} onPickNode={selectNode} onPickEdge={selectEdge} />
        </>
      )}
      {canExplore && mode === 'details' && model && map && <DetailsView map={map} model={model} selected={activeSelection} onPick={selectEdge} />}
      {canExplore && map && model && <Inspector selection={selection} map={map} model={model} audit={audit} outsideFilter={outsideFilter} />}
    </section>
  );
}
