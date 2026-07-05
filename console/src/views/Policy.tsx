import { useCallback, useEffect, useState } from 'react';
import {
  applyPolicyTemplate,
  fetchPolicy,
  fetchPolicyTemplates,
  postPolicyImpact,
  putPolicy,
  type EnforcementMode,
  type ImpactDelta,
  type ImpactOutcome,
  type Policy as PolicyDoc,
  type PolicyImpact,
  type PolicyTemplate,
  type PolicyUpdate,
  type ResponseScanMode,
} from '../api/policy';
import { EmptyState, Panel } from '../components/Panel';
import { apiErrorSummary } from '../lib/api';
import { useSession } from '../lib/session';
import { toast } from '../lib/toast';
import './Policy.css';

/**
 * Policy editor (port of the legacy #tab-policy form). Form-edits the core
 * enforcement fields; everything else in the policy document stays visible in
 * a read-only JSON block. No SSE auto-reload: refreshing the form mid-edit
 * would silently discard operator changes.
 */

const MODES: [EnforcementMode, string, string][] = [
  ['warn', 'Monitor', 'Warn users and allow them to continue'],
  ['justify', 'Justify', 'Require a business reason before send'],
  ['redact', 'Redact', 'Tokenize PII before release'],
  ['block', 'Enforce', 'Hold risky prompts for approval'],
];

const SEVERITIES: [number, string][] = [
  [1, 'low'],
  [2, 'medium'],
  [3, 'high'],
  [4, 'critical'],
];

const SCAN_MODES: [ResponseScanMode, string][] = [
  ['flag', 'Flag and alert'],
  ['redact', 'Redact before display'],
  ['block', 'Block display'],
];

const OUTCOMES: [ImpactOutcome, string][] = [
  ['blocked', 'Blocked'],
  ['approval_required', 'Approval required'],
  ['justification_required', 'Justification required'],
  ['redacted', 'Redacted'],
  ['warned', 'Warned'],
  ['allowed', 'Allowed'],
  ['observed', 'Observed'],
];

type DestListKey =
  | 'governedDestinations'
  | 'allowedDestinations'
  | 'blockedDestinations'
  | 'blockedFileUploadDestinations';

const DESTINATION_FIELDS: [DestListKey, string, string][] = [
  ['governedDestinations', 'Governed AI destinations', 'chatgpt.com\nclaude.ai'],
  ['allowedDestinations', 'Allowed AI destinations', 'chatgpt.com\nclaude.ai'],
  ['blockedDestinations', 'Blocked AI destinations', 'deepseek.com\n*.example-ai.com'],
  ['blockedFileUploadDestinations', 'Blocked file uploads', 'chatgpt.com\ndesktop-ai-app'],
];

/** Form fields (plus alwaysBlock chips) excluded from the advanced JSON block. */
const FORM_EDITED_FIELDS = new Set<string>([
  'enforcementMode',
  'blockMinSeverity',
  'blockRiskScore',
  'storeRawForApproval',
  'rawRetentionDays',
  'governedDestinations',
  'allowedDestinations',
  'blockedDestinations',
  'blockedFileUploadDestinations',
  'blockUnapprovedAiDestinations',
  'responseScanMode',
  'desktopCollectorDestination',
  'alwaysBlock',
]);

/** Text-input mirror of the editable policy fields. */
interface Draft {
  enforcementMode: EnforcementMode;
  blockMinSeverity: number;
  blockRiskScore: string;
  storeRawForApproval: boolean;
  rawRetentionDays: string;
  blockUnapprovedAiDestinations: boolean;
  responseScanMode: ResponseScanMode;
  desktopCollectorDestination: string;
  governedDestinations: string;
  allowedDestinations: string;
  blockedDestinations: string;
  blockedFileUploadDestinations: string;
}

function listText(items: string[]): string {
  return (items || []).join('\n');
}

/** Mirrors legacy parsePolicyList: newline/comma separated, trimmed, deduped. */
function parseList(value: string): string[] {
  return [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
}

/** Blank stays invalid (NaN -> JSON null -> 400 naming the field) instead of silently becoming 0. */
function numberField(value: string): number {
  return value.trim() === '' ? Number.NaN : Number(value);
}

function draftFromPolicy(policy: PolicyDoc): Draft {
  return {
    enforcementMode: policy.enforcementMode,
    blockMinSeverity: policy.blockMinSeverity,
    blockRiskScore: String(policy.blockRiskScore),
    storeRawForApproval: policy.storeRawForApproval !== false,
    rawRetentionDays: String(policy.rawRetentionDays),
    blockUnapprovedAiDestinations: policy.blockUnapprovedAiDestinations !== false,
    responseScanMode: policy.responseScanMode,
    desktopCollectorDestination: policy.desktopCollectorDestination || 'Desktop AI',
    governedDestinations: listText(policy.governedDestinations),
    allowedDestinations: listText(policy.allowedDestinations),
    blockedDestinations: listText(policy.blockedDestinations),
    blockedFileUploadDestinations: listText(policy.blockedFileUploadDestinations),
  };
}

function updateFromDraft(draft: Draft): PolicyUpdate {
  return {
    enforcementMode: draft.enforcementMode,
    blockMinSeverity: draft.blockMinSeverity,
    blockRiskScore: numberField(draft.blockRiskScore),
    storeRawForApproval: draft.storeRawForApproval,
    rawRetentionDays: numberField(draft.rawRetentionDays),
    blockUnapprovedAiDestinations: draft.blockUnapprovedAiDestinations,
    responseScanMode: draft.responseScanMode,
    desktopCollectorDestination: draft.desktopCollectorDestination.trim(),
    governedDestinations: parseList(draft.governedDestinations),
    allowedDestinations: parseList(draft.allowedDestinations),
    blockedDestinations: parseList(draft.blockedDestinations),
    blockedFileUploadDestinations: parseList(draft.blockedFileUploadDestinations),
  };
}

function isDirty(policy: PolicyDoc, draft: Draft): boolean {
  return JSON.stringify(updateFromDraft(draft)) !== JSON.stringify(updateFromDraft(draftFromPolicy(policy)));
}

function metaLine(policy: PolicyDoc): string {
  return `${policy.enforcementMode} mode / severity >= ${policy.blockMinSeverity} / risk >= ${policy.blockRiskScore}`;
}

async function requestJson<T>(request: Promise<Response | null>, fallback: string): Promise<T | null> {
  const res = await request;
  if (!res || !res.ok) {
    toast(await apiErrorSummary(res, fallback), 'error');
    return null;
  }
  try {
    return (await res.json()) as T;
  } catch {
    toast(fallback, 'error');
    return null;
  }
}

interface MutationCtx {
  draft: Draft | null;
  adopt: (policy: PolicyDoc) => void;
  load: () => Promise<void>;
  setImpact: (impact: PolicyImpact | null) => void;
  setBusy: (busy: boolean) => void;
}

function usePolicyMutations({ draft, adopt, load, setImpact, setBusy }: MutationCtx) {
  const wrap = (action: () => Promise<void>) => async () => {
    setBusy(true);
    try {
      await action();
    } finally {
      setBusy(false);
    }
  };
  const save = wrap(async () => {
    if (!draft) return;
    const saved = await requestJson<PolicyDoc>(putPolicy(updateFromDraft(draft)), 'Could not save policy');
    if (!saved) return;
    adopt(saved);
    toast('Policy saved.', 'good');
  });
  const preview = wrap(async () => {
    if (!draft) return;
    const impact = await requestJson<PolicyImpact>(postPolicyImpact(updateFromDraft(draft)), 'Could not preview impact');
    if (impact) setImpact(impact);
  });
  const applyTemplate = (id: string) =>
    wrap(async () => {
      const merged = await requestJson<PolicyDoc>(applyPolicyTemplate(id), 'Could not apply template');
      if (!merged) return;
      toast('Template applied.', 'good');
      setImpact(null);
      await load(); // refetch: the saved policy is re-normalized server-side
    })();
  return { save, preview, applyTemplate };
}

function usePolicyEditor() {
  const [policy, setPolicy] = useState<PolicyDoc | null>(null);
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [impact, setImpact] = useState<PolicyImpact | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);

  const adopt = useCallback((next: PolicyDoc) => {
    setPolicy(next);
    setDraft(draftFromPolicy(next));
  }, []);
  const load = useCallback(async () => {
    const [pol, tpls] = await Promise.all([fetchPolicy(), fetchPolicyTemplates()]);
    if (pol) adopt(pol);
    if (tpls) setTemplates(tpls);
    setLoaded(true);
  }, [adopt]);
  useEffect(() => {
    load();
  }, [load]);

  const mutations = usePolicyMutations({ draft, adopt, load, setImpact, setBusy });
  const patch = (change: Partial<Draft>) => setDraft((current) => (current ? { ...current, ...change } : current));
  const discard = () => {
    if (policy) setDraft(draftFromPolicy(policy));
    setImpact(null);
  };
  return { policy, templates, draft, impact, loaded, busy, patch, discard, ...mutations };
}

interface FieldProps {
  draft: Draft;
  disabled: boolean;
  patch: (change: Partial<Draft>) => void;
}

function CheckboxField(props: { id: string; label: string; checked: boolean; disabled: boolean; onChange: (checked: boolean) => void }) {
  return (
    <>
      <label htmlFor={props.id}>{props.label}</label>
      <input
        id={props.id}
        type="checkbox"
        checked={props.checked}
        disabled={props.disabled}
        onChange={(event) => props.onChange(event.target.checked)}
      />
    </>
  );
}

interface InputFieldProps {
  id: string;
  label: string;
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}

function NumberField({ id, label, value, disabled, onChange, min, max }: InputFieldProps & { min: number; max: number }) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="number" min={min} max={max} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </>
  );
}

function TextField({ id, label, value, disabled, onChange, maxLength }: InputFieldProps & { maxLength: number }) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="text" maxLength={maxLength} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </>
  );
}

function SelectField(props: {
  id: string;
  label: string;
  value: string | number;
  options: readonly (readonly [string | number, string])[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <>
      <label htmlFor={props.id}>{props.label}</label>
      <select id={props.id} value={props.value} disabled={props.disabled} onChange={(event) => props.onChange(event.target.value)}>
        {props.options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </>
  );
}

function ModePicker({ mode, disabled, onChange }: { mode: EnforcementMode; disabled: boolean; onChange: (mode: EnforcementMode) => void }) {
  return (
    <section className="policy-section">
      <h3>Policy mode</h3>
      <p className="policy-hint">
        What every RedactWall sensor does when it sees sensitive content. Hard-stop identifiers still block regardless of mode.
      </p>
      <div className="policy-modes" role="radiogroup" aria-label="Enforcement mode">
        {MODES.map(([value, title, detail]) => (
          <label key={value} className={`policy-mode${mode === value ? ' selected' : ''}`}>
            <span>
              <input
                type="radio"
                name="policy-mode"
                value={value}
                checked={mode === value}
                disabled={disabled}
                onChange={() => onChange(value)}
              />
              {title}
            </span>
            <p>{detail}</p>
          </label>
        ))}
      </div>
    </section>
  );
}

function ThresholdFields({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>Blocking thresholds</h3>
      <div className="policy-field-grid">
        <SelectField
          id="pol-sev"
          label="Block at minimum severity"
          options={SEVERITIES}
          value={draft.blockMinSeverity}
          disabled={disabled}
          onChange={(value) => patch({ blockMinSeverity: Number(value) })}
        />
        <NumberField
          id="pol-risk"
          label="Block at risk score greater than or equal to"
          min={0}
          max={100}
          value={draft.blockRiskScore}
          disabled={disabled}
          onChange={(value) => patch({ blockRiskScore: value })}
        />
      </div>
    </section>
  );
}

function HandlingFields({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>Retention and handling</h3>
      <div className="policy-field-grid">
        <CheckboxField
          id="pol-store-raw"
          label="Retain raw prompts for approval review (encrypted at rest)"
          checked={draft.storeRawForApproval}
          disabled={disabled}
          onChange={(checked) => patch({ storeRawForApproval: checked })}
        />
        <NumberField
          id="pol-retention"
          label="Purge retained raw approval data after days"
          min={0}
          max={3650}
          value={draft.rawRetentionDays}
          disabled={disabled}
          onChange={(value) => patch({ rawRetentionDays: value })}
        />
        <CheckboxField
          id="pol-block-unapproved"
          label="Block unapproved AI destinations"
          checked={draft.blockUnapprovedAiDestinations}
          disabled={disabled}
          onChange={(checked) => patch({ blockUnapprovedAiDestinations: checked })}
        />
        <SelectField
          id="pol-response-scan"
          label="When AI responses contain sensitive data"
          options={SCAN_MODES}
          value={draft.responseScanMode}
          disabled={disabled}
          onChange={(value) => patch({ responseScanMode: value as ResponseScanMode })}
        />
        <TextField
          id="pol-desktop"
          label="Default desktop upload destination"
          maxLength={80}
          value={draft.desktopCollectorDestination}
          disabled={disabled}
          onChange={(value) => patch({ desktopCollectorDestination: value })}
        />
      </div>
    </section>
  );
}

function listPatch(key: DestListKey, value: string): Partial<Draft> {
  const change: Partial<Draft> = {};
  change[key] = value;
  return change;
}

function DestinationLists({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>Destination governance</h3>
      <p className="policy-hint">One destination per line; * wildcards allowed. Allowed entries override blocks.</p>
      <div className="policy-list-grid">
        {DESTINATION_FIELDS.map(([key, label, placeholder]) => (
          <label key={key} className="policy-list-field">
            <span>{label}</span>
            <textarea
              value={draft[key]}
              placeholder={placeholder}
              spellCheck={false}
              disabled={disabled}
              onChange={(event) => patch(listPatch(key, event.target.value))}
            />
          </label>
        ))}
      </div>
    </section>
  );
}

function HardStops({ items }: { items: string[] }) {
  return (
    <section className="policy-section">
      <h3>Hard-stop entities</h3>
      <p className="policy-hint">
        These identifiers block or tokenize even when the global mode is softer. Change them by applying a template or via the API.
      </p>
      <div className="policy-chips">
        {items.length ? (
          items.map((item) => (
            <span key={item} className="policy-chip static">
              {item}
            </span>
          ))
        ) : (
          <span className="policy-chip static">none</span>
        )}
      </div>
    </section>
  );
}

function TemplatePicker({ templates, disabled, onApply }: { templates: PolicyTemplate[]; disabled: boolean; onApply: (id: string) => void }) {
  const [pending, setPending] = useState<PolicyTemplate | null>(null);
  if (!templates.length) return null;
  return (
    <section className="policy-section">
      <h3>Policy templates</h3>
      <p className="policy-hint">Start from a compliance preset, then tune thresholds and destinations. Applying saves immediately.</p>
      <div className="policy-chips">
        {templates.map((template) => (
          <button
            key={template.id}
            type="button"
            className={`policy-chip${pending?.id === template.id ? ' selected' : ''}`}
            title={template.description}
            disabled={disabled}
            onClick={() => setPending(template)}
          >
            {template.label}
          </button>
        ))}
      </div>
      {pending ? (
        <TemplateConfirm
          template={pending}
          disabled={disabled}
          onCancel={() => setPending(null)}
          onApply={() => {
            setPending(null);
            onApply(pending.id);
          }}
        />
      ) : null}
    </section>
  );
}

function TemplateConfirm(props: { template: PolicyTemplate; disabled: boolean; onApply: () => void; onCancel: () => void }) {
  return (
    <div className="policy-confirm" role="alert">
      <span>
        Apply <strong>{props.template.label}</strong> over the saved policy? {props.template.description}
      </span>
      <button type="button" className="policy-btn primary" disabled={props.disabled} onClick={props.onApply}>
        Apply template
      </button>
      <button type="button" className="policy-btn" onClick={props.onCancel}>
        Cancel
      </button>
    </div>
  );
}

function ImpactSummary({ summary }: { summary: PolicyImpact['summary'] }) {
  const tiles: [string, number, string][] = [
    ['Changed outcomes', summary.changed, 'info'],
    ['Newly blocked', summary.newlyBlocked, 'critical'],
    ['Newly allowed', summary.newlyAllowed, 'secure'],
    ['More restrictive', summary.moreRestrictive, 'warn'],
    ['Less restrictive', summary.lessRestrictive, 'warn'],
  ];
  return (
    <div className="policy-impact-tiles">
      {tiles.map(([label, value, tone]) => (
        <div key={label} className={`policy-impact-tile tone-${tone}`}>
          <b>{value}</b>
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}

function OutcomeTable({ current, proposed }: { current: Record<ImpactOutcome, number>; proposed: Record<ImpactOutcome, number> }) {
  return (
    <div className="policy-outcomes">
      <div className="policy-outcome-row policy-outcome-head">
        <span>Outcome</span>
        <span>Current</span>
        <span>Proposed</span>
        <span>Delta</span>
      </div>
      {OUTCOMES.map(([key, label]) => {
        const from = current[key] || 0;
        const to = proposed[key] || 0;
        const delta = to - from;
        return (
          <div className="policy-outcome-row" key={key}>
            <span>{label}</span>
            <span>{from}</span>
            <span>{to}</span>
            <span className={delta > 0 ? 'delta-up' : delta < 0 ? 'delta-down' : 'delta-flat'}>
              {delta > 0 ? `+${delta}` : delta}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function deltaRows(items: ImpactDelta[]): [string, string][] {
  return (items || [])
    .filter((item) => item.changed > 0)
    .map((item) => [item.label, `${item.changed} changed / +${item.newlyBlocked} blocked / +${item.newlyAllowed} allowed`]);
}

function DeltaGroup({ label, rows }: { label: string; rows: [string, string][] }) {
  return (
    <div className="policy-delta-group">
      <strong>{label}</strong>
      {rows.map(([name, detail]) => (
        <div key={name} className="policy-delta-row">
          <span className="policy-delta-label">{name}</span>
          <span>{detail}</span>
        </div>
      ))}
    </div>
  );
}

function ImpactDeltas({ deltas }: { deltas: PolicyImpact['topDeltas'] }) {
  const groups: [string, [string, string][]][] = [
    ['Destinations', deltaRows(deltas.destinations)],
    ['Detections', deltaRows(deltas.categories)],
    ['Sources', deltaRows(deltas.sources)],
    ['Change reasons', (deltas.reasons || []).map((r) => [r.reason.replace(/_/g, ' '), String(r.count)] as [string, string])],
  ];
  const nonEmpty = groups.filter(([, rows]) => rows.length);
  if (!nonEmpty.length) return null;
  return (
    <div className="policy-impact-deltas">
      {nonEmpty.map(([label, rows]) => (
        <DeltaGroup key={label} label={label} rows={rows} />
      ))}
    </div>
  );
}

function ImpactPreview({ impact }: { impact: PolicyImpact }) {
  return (
    <section className="policy-section policy-impact" aria-live="polite">
      <h3>Impact preview</h3>
      <p className="policy-hint">
        Draft policy replayed against {impact.summary.sampleSize} recent events. Metadata only — prompt bodies are excluded.
      </p>
      <ImpactSummary summary={impact.summary} />
      <OutcomeTable current={impact.summary.current} proposed={impact.summary.proposed} />
      <ImpactDeltas deltas={impact.topDeltas} />
    </section>
  );
}

function advancedFields(policy: PolicyDoc): Record<string, unknown> {
  return Object.fromEntries(Object.entries(policy).filter(([key]) => !FORM_EDITED_FIELDS.has(key)));
}

function AdvancedJson({ policy }: { policy: PolicyDoc }) {
  return (
    <details className="policy-advanced">
      <summary>Advanced policy fields (read-only)</summary>
      <p className="policy-hint">
        Detector ignore lists, MCP tool governance, browser action controls, approval routing, scopes, exceptions, sensor fleet, and
        scanner settings are edited in the classic console or via the API. Saving here leaves them unchanged.
      </p>
      <pre>{JSON.stringify(advancedFields(policy), null, 2)}</pre>
    </details>
  );
}

interface ActionRowProps {
  readOnly: boolean;
  busy: boolean;
  dirty: boolean;
  onSave: () => void;
  onPreview: () => void;
  onDiscard: () => void;
}

function ActionRow({ readOnly, busy, dirty, onSave, onPreview, onDiscard }: ActionRowProps) {
  return (
    <div className="policy-actions">
      <button type="button" className="policy-btn" disabled={busy || !dirty} onClick={onDiscard}>
        Discard changes
      </button>
      <button type="button" className="policy-btn" disabled={busy || readOnly} onClick={onPreview}>
        Preview impact
      </button>
      {readOnly ? (
        <span className="policy-readonly-note">Read-only view — Security Admin required to edit</span>
      ) : (
        <button type="button" className="policy-btn primary" disabled={busy} onClick={onSave}>
          Save changes
        </button>
      )}
    </div>
  );
}

interface EditorProps extends ActionRowProps {
  policy: PolicyDoc;
  draft: Draft;
  templates: PolicyTemplate[];
  impact: PolicyImpact | null;
  patch: (change: Partial<Draft>) => void;
  onApplyTemplate: (id: string) => void;
}

function PolicyEditor(props: EditorProps) {
  const { draft, readOnly, busy, patch } = props;
  const disabled = readOnly || busy;
  return (
    <div className="policy-editor">
      <ActionRow
        readOnly={readOnly}
        busy={busy}
        dirty={props.dirty}
        onSave={props.onSave}
        onPreview={props.onPreview}
        onDiscard={props.onDiscard}
      />
      {props.impact ? <ImpactPreview impact={props.impact} /> : null}
      <ModePicker mode={draft.enforcementMode} disabled={disabled} onChange={(mode) => patch({ enforcementMode: mode })} />
      <ThresholdFields draft={draft} disabled={disabled} patch={patch} />
      <HandlingFields draft={draft} disabled={disabled} patch={patch} />
      <DestinationLists draft={draft} disabled={disabled} patch={patch} />
      <HardStops items={props.policy.alwaysBlock} />
      <TemplatePicker templates={props.templates} disabled={disabled} onApply={props.onApplyTemplate} />
      <AdvancedJson policy={props.policy} />
    </div>
  );
}

export default function Policy() {
  const { me } = useSession();
  const editor = usePolicyEditor();
  const { policy, draft, loaded } = editor;
  const readOnly = !me || me.role !== 'security_admin';

  return (
    <Panel title="Policy" meta={!loaded ? 'Loading' : policy ? metaLine(policy) : 'Waiting for data'}>
      {loaded && !policy ? (
        <EmptyState title="Policy unavailable" detail="The enforcement policy could not be loaded. Refresh or check the server." />
      ) : policy && draft ? (
        <PolicyEditor
          policy={policy}
          draft={draft}
          templates={editor.templates}
          impact={editor.impact}
          readOnly={readOnly}
          busy={editor.busy}
          dirty={isDirty(policy, draft)}
          patch={editor.patch}
          onSave={editor.save}
          onPreview={editor.preview}
          onDiscard={editor.discard}
          onApplyTemplate={editor.applyTemplate}
        />
      ) : null}
    </Panel>
  );
}
