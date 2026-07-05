import { useCallback, useState } from 'react';
import {
  BULK_DECISION_LIMIT,
  approveQuery,
  bulkDecision,
  denyQuery,
  revealQuery,
  type BulkDecisionResult,
  type DecisionResult,
  type QueueQuery,
  type RevealResult,
} from '../../api/queries';
import { toast } from '../../lib/toast';

/**
 * Decision state + handlers for the approval queue. Passwords pass straight
 * through to the API and are never stored; revealed raw prompts live only in
 * this hook's in-memory map and are pruned as soon as the item leaves the list.
 */

export type StepUpRequest =
  | { kind: 'approve-one'; id: string }
  | { kind: 'approve-bulk'; ids: string[] }
  | { kind: 'reveal'; id: string };

export interface StepUpCopy {
  title: string;
  message: string;
  confirmLabel: string;
  confirmClass: 'approve' | 'reveal';
}

export function stepUpCopy(request: StepUpRequest): StepUpCopy {
  if (request.kind === 'reveal') {
    return {
      title: 'Confirm raw reveal',
      message: 'This action is audit-logged and may display sensitive prompt content.',
      confirmLabel: 'Reveal',
      confirmClass: 'reveal',
    };
  }
  const count = request.kind === 'approve-bulk' ? request.ids.length : 1;
  return {
    title: 'Confirm release',
    message:
      count > 1
        ? `Approving releases ${count} held prompts to their requesting sensors.`
        : 'Approving releases this held prompt to the requesting sensor.',
    confirmLabel: 'Approve release',
    confirmClass: 'approve',
  };
}

function bulkOutcomeToast(outcome: BulkDecisionResult, verb: string): void {
  const reasons = [...new Set(outcome.results.map((r) => r.reason).filter((r): r is string => Boolean(r)))].join(', ');
  const skippedNote = outcome.skipped ? ` ${outcome.skipped} skipped (${reasons}).` : '';
  toast(`${outcome.decided} prompt(s) ${verb}.${skippedNote}`, outcome.skipped ? 'warn' : 'good');
}

function validateBulk(ids: string[]): boolean {
  if (!ids.length) return false;
  if (ids.length > BULK_DECISION_LIMIT) {
    toast(`Bulk decisions are limited to ${BULK_DECISION_LIMIT} prompts at a time.`, 'warn');
    return false;
  }
  return true;
}

export function useQueueActions(load: () => void) {
  const [note, setNote] = useState('');
  const [bulkNote, setBulkNote] = useState('');
  const [checked, setChecked] = useState<ReadonlySet<string>>(() => new Set());
  const [reveals, setReveals] = useState<ReadonlyMap<string, RevealResult>>(() => new Map());
  const [stepUp, setStepUp] = useState<StepUpRequest | null>(null);
  const [busy, setBusy] = useState(false);

  const clearAfterDecision = (ids: string[]) => {
    setNote('');
    setChecked((prev) => new Set([...prev].filter((id) => !ids.includes(id))));
    setReveals((prev) => new Map([...prev].filter(([id]) => !ids.includes(id))));
    load();
  };

  const finishBulk = (result: DecisionResult<BulkDecisionResult>, verb: string, ids: string[]) => {
    if (!result.data) {
      toast(result.error || 'Bulk decision failed.', 'error');
      return;
    }
    bulkOutcomeToast(result.data, verb);
    setBulkNote('');
    clearAfterDecision(ids);
  };

  const deny = async (id: string) => {
    setBusy(true);
    const result = await denyQuery(id, note.trim());
    setBusy(false);
    if (result.error) {
      toast(result.error, 'error');
      return;
    }
    toast('Prompt denied.', 'good');
    clearAfterDecision([id]);
  };

  const bulkDeny = async () => {
    const ids = [...checked];
    if (!validateBulk(ids)) return;
    setBusy(true);
    finishBulk(await bulkDecision(ids, 'deny', bulkNote.trim()), 'denied', ids);
    setBusy(false);
  };

  const requestBulkApprove = () => {
    const ids = [...checked];
    if (validateBulk(ids)) setStepUp({ kind: 'approve-bulk', ids });
  };

  const runApprove = async (id: string, password: string) => {
    const result = await approveQuery(id, note.trim(), password);
    if (result.error) {
      toast(result.error, 'error');
      return;
    }
    toast('Prompt approved and released.', 'good');
    clearAfterDecision([id]);
  };

  const runReveal = async (id: string, password: string) => {
    const result = await revealQuery(id, password);
    const data = result.data;
    if (!data) {
      toast(result.error || 'Reveal failed.', 'error');
      return;
    }
    setReveals((prev) => new Map(prev).set(id, data));
  };

  const confirmStepUp = async (password: string) => {
    const request = stepUp;
    setStepUp(null);
    if (!request) return;
    setBusy(true);
    if (request.kind === 'reveal') await runReveal(request.id, password);
    else if (request.kind === 'approve-one') await runApprove(request.id, password);
    else finishBulk(await bulkDecision(request.ids, 'approve', bulkNote.trim(), password), 'approved', request.ids);
    setBusy(false);
  };

  /** Drop checks and revealed text for items no longer in (or no longer pending in) the list. */
  const pruneTo = useCallback((rows: QueueQuery[]) => {
    const ids = new Set(rows.map((q) => q.id));
    const pending = new Set(rows.filter((q) => q.status === 'pending').map((q) => q.id));
    setChecked((prev) => new Set([...prev].filter((id) => pending.has(id))));
    setReveals((prev) => new Map([...prev].filter(([id]) => ids.has(id))));
  }, []);

  const toggleChecked = (id: string, value: boolean) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (value) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  return {
    note, setNote, bulkNote, setBulkNote, checked, reveals, stepUp, setStepUp, busy,
    deny, bulkDeny, requestBulkApprove, confirmStepUp, pruneTo, toggleChecked,
  };
}
