/**
 * Aggregate traffic fields emitted by server/posture.js.
 *
 * The continued count includes only explicit policy outcomes that authorize a
 * sanitized flow to proceed. It is deliberately not inferred from
 * total-minus-blocked: warnings, paste coaching, shadow sightings, and unknown
 * observations do not prove continuation. It is also not delivery
 * confirmation.
 */
export interface LeakMapTrafficCounts {
  continued?: unknown;
}

interface DecodedCategory {
  label: string;
  events: number;
}

interface DecodedNode {
  id: string;
  label: string;
  status: string;
  events: number;
  sensitive: number;
  controlled: number;
  blocked: number;
  redacted: number;
  coached: number;
  pending: number;
  shadow: number;
  uncontrolled: number;
  continued: number;
  uncontrolledContinued: number;
  users: number;
  controlRate: number;
  lastSeen: string | null;
  typeLabel?: string;
  state?: string;
}

interface DecodedEdge extends DecodedNode {
  from: string;
  to: string;
  via: string;
  viaLabel?: string;
  categories: DecodedCategory[];
}

interface DecodedSummary {
  segments: number;
  destinations: number;
  edges: number;
  shownEdges: number;
  events: number;
  sensitive: number;
  controlled: number;
  uncontrolled: number;
  continued: number;
  uncontrolledContinued: number;
  pending: number;
  shadow: number;
  controlRate: number;
  status: string;
  privacy: string;
}

export interface DecodedLeakMapReport {
  segments: DecodedNode[];
  channels: DecodedNode[];
  destinations: DecodedNode[];
  edges: DecodedEdge[];
  categories: DecodedCategory[];
  summary: DecodedSummary;
}

const MAX_COUNT = 1_000_000_000;
const MAP_LIMITS = Object.freeze({ segments: 6, channels: 16, destinations: 8, edges: 18, categories: 6 });
const VALID_STATUSES = new Set(['online', 'warning', 'error', 'idle']);
const VALID_DESTINATION_STATES = new Set(['sanctioned', 'unsanctioned', 'shadow', 'observed']);
const TRAFFIC_COUNT_KEYS = [
  'events', 'sensitive', 'controlled', 'blocked', 'redacted', 'coached',
  'pending', 'shadow', 'uncontrolled', 'continued', 'uncontrolledContinued', 'users',
] as const;
const SUMMARY_COUNT_KEYS = [
  'segments', 'destinations', 'edges', 'shownEdges', 'events', 'sensitive',
  'controlled', 'uncontrolled', 'continued', 'uncontrolledContinued', 'pending', 'shadow',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value: unknown, max: number): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return null;
  if (value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) return null;
  return value;
}

function optionalText(value: unknown, max: number): string | undefined | null {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return boundedText(value, max);
}

function exactCount(value: unknown): number | null {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= MAX_COUNT
    ? value
    : null;
}

function exactRate(value: unknown): number | null {
  const count = exactCount(value);
  return count !== null && count <= 100 ? count : null;
}

function decodeCounts<T extends readonly string[]>(value: Record<string, unknown>, keys: T): Record<T[number], number> | null {
  const decoded = Object.fromEntries(keys.map((key) => [key, exactCount(value[key])])) as Record<T[number], number | null>;
  return Object.values(decoded).some((count) => count === null) ? null : decoded as Record<T[number], number>;
}

function decodeCategory(value: unknown): DecodedCategory | null {
  if (!isRecord(value)) return null;
  const label = boundedText(value.label, 72);
  const events = exactCount(value.events);
  return label !== null && events !== null ? { label, events } : null;
}

function validCountRelationships(item: DecodedNode): boolean {
  const expectedRate = item.sensitive ? Math.round((item.controlled / item.sensitive) * 100) : 100;
  // These are overlapping dimensions, not disjoint outcomes. For example, a
  // pending justification is both blocked from egress and a coaching event.
  const statusIsConservative = item.uncontrolled > 0 || item.shadow > 0
    ? item.status === 'error'
    : item.pending > 0
      ? item.status === 'warning' || item.status === 'error'
      : item.events === 0
        ? item.status === 'idle'
        : item.status !== 'idle';
  return item.controlRate === expectedRate
    && statusIsConservative
    && item.sensitive <= item.events
    && item.controlled <= item.sensitive
    && item.uncontrolled <= item.sensitive
    && item.controlled + item.uncontrolled <= item.sensitive
    && item.blocked <= item.controlled
    && item.redacted <= item.controlled
    && item.coached <= item.controlled
    && item.pending <= item.events
    && item.shadow <= item.events
    && item.continued <= item.events
    && item.uncontrolledContinued <= item.uncontrolled
    && item.uncontrolledContinued <= item.continued;
}

function decodeNode(value: unknown, kind: 'segment' | 'channel' | 'destination' | 'edge'): DecodedNode | null {
  if (!isRecord(value)) return null;
  const id = boundedText(value.id, 180);
  const label = kind === 'edge' ? id : boundedText(value.label, 140);
  const status = boundedText(value.status, 16);
  const lastSeen = optionalText(value.lastSeen, 64);
  const typeLabel = optionalText(value.typeLabel, 40);
  const state = optionalText(value.state, 40);
  const counts = decodeCounts(value, TRAFFIC_COUNT_KEYS);
  const controlRate = exactRate(value.controlRate);
  if (
    id === null
    || label === null
    || status === null
    || !VALID_STATUSES.has(status)
    || lastSeen === undefined
    || (typeLabel === null || state === null)
    || counts === null
    || controlRate === null
  ) return null;
  if (kind === 'segment' && typeLabel === undefined) return null;
  if (kind !== 'segment' && typeLabel !== undefined) return null;
  if (kind === 'destination' && (state === undefined || !VALID_DESTINATION_STATES.has(state))) return null;
  if (kind !== 'destination' && state !== undefined) return null;
  const decoded: DecodedNode = {
    id,
    label,
    status,
    ...counts,
    controlRate,
    lastSeen,
  };
  if (typeLabel !== undefined) decoded.typeLabel = typeLabel;
  if (state !== undefined) decoded.state = state;
  return validCountRelationships(decoded) ? decoded : null;
}

function decodeEdge(value: unknown): DecodedEdge | null {
  const node = decodeNode(value, 'edge');
  if (!node || !isRecord(value) || !Array.isArray(value.categories) || value.categories.length > 3) return null;
  const from = boundedText(value.from, 180);
  const to = boundedText(value.to, 180);
  const via = boundedText(value.via, 40);
  const viaLabel = optionalText(value.viaLabel, 40);
  const categories = value.categories.map(decodeCategory);
  if (from === null || to === null || via === null || viaLabel === null || categories.some((item) => item === null)) return null;
  const decodedCategories = categories as DecodedCategory[];
  if (new Set(decodedCategories.map((item) => item.label)).size !== decodedCategories.length) return null;
  if (decodedCategories.some((item) => item.events > node.events)) return null;
  const edge: DecodedEdge = { ...node, from, to, via, categories: decodedCategories };
  if (viaLabel !== undefined) edge.viaLabel = viaLabel;
  return edge;
}

function decodeArray<T>(value: unknown, limit: number, decoder: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value) || value.length > limit) return null;
  const decoded = value.map(decoder);
  return decoded.some((item) => item === null) ? null : decoded as T[];
}

function uniqueIds(rows: Array<{ id: string }>): boolean {
  return new Set(rows.map((item) => item.id)).size === rows.length;
}

function decodeSummary(value: unknown): DecodedSummary | null {
  if (!isRecord(value)) return null;
  const counts = decodeCounts(value, SUMMARY_COUNT_KEYS);
  const controlRate = exactRate(value.controlRate);
  const status = boundedText(value.status, 16);
  const privacy = boundedText(value.privacy, 120);
  if (!counts || controlRate === null || status === null || privacy === null || !VALID_STATUSES.has(status)) return null;
  const summary: DecodedSummary = {
    ...counts,
    controlRate,
    status,
    privacy,
  };
  return validCountRelationships({
    ...summary,
    id: 'all',
    label: 'All flows',
    blocked: 0,
    redacted: 0,
    coached: 0,
    users: 0,
    lastSeen: null,
  }) ? summary : null;
}

function withinSummary(item: DecodedNode | DecodedCategory, summary: DecodedSummary): boolean {
  if ('sensitive' in item) {
    return item.events <= summary.events
      && item.sensitive <= summary.sensitive
      && item.controlled <= summary.controlled
      && item.uncontrolled <= summary.uncontrolled
      && item.continued <= summary.continued
      && item.uncontrolledContinued <= summary.uncontrolledContinued
      && item.pending <= summary.pending
      && item.shadow <= summary.shadow;
  }
  return item.events <= summary.events;
}

/**
 * Decode the complete sanitized leak-map contract. The returned object contains
 * only renderer-supported fields. Any malformed count, unsupported status,
 * duplicate id, or dangling relationship rejects the whole snapshot so the UI
 * cannot turn ambiguous network data into a green or empty state.
 */
export function decodeLeakMapReport(value: unknown): DecodedLeakMapReport | null {
  if (!isRecord(value)) return null;
  const segments = decodeArray(value.segments, MAP_LIMITS.segments, (item) => decodeNode(item, 'segment'));
  const channels = decodeArray(value.channels, MAP_LIMITS.channels, (item) => decodeNode(item, 'channel'));
  const destinations = decodeArray(value.destinations, MAP_LIMITS.destinations, (item) => decodeNode(item, 'destination'));
  const edges = decodeArray(value.edges, MAP_LIMITS.edges, decodeEdge);
  const categories = decodeArray(value.categories, MAP_LIMITS.categories, decodeCategory);
  const summary = decodeSummary(value.summary);
  if (!segments || !channels || !destinations || !edges || !categories || !summary) return null;
  if (!uniqueIds(segments) || !uniqueIds(channels) || !uniqueIds(destinations) || !uniqueIds(edges)) return null;
  if (new Set(categories.map((item) => item.label)).size !== categories.length) return null;
  if (summary.segments < segments.length || summary.destinations < destinations.length || summary.edges < edges.length || summary.shownEdges !== edges.length) return null;
  const segmentIds = new Set(segments.map((item) => item.id));
  const channelIds = new Set(channels.map((item) => item.id));
  const destinationIds = new Set(destinations.map((item) => item.id));
  if (edges.some((edge) => !segmentIds.has(edge.from) || !channelIds.has(edge.via) || !destinationIds.has(edge.to))) return null;
  if (new Set(edges.map((edge) => `${edge.from}\u0000${edge.to}`)).size !== edges.length) return null;
  if ([...segments, ...channels, ...destinations, ...edges, ...categories].some((item) => !withinSummary(item, summary))) return null;
  return { segments, channels, destinations, edges, categories, summary };
}

/** Events with an explicit server-recorded safe-to-continue outcome. */
export function continuedEventCount(edge: LeakMapTrafficCounts): number {
  return exactCount(edge.continued) ?? 0;
}
