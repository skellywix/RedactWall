import { Fragment, useId, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent, type ReactElement, type RefObject } from 'react';
import { useModalFocus } from './system/useModalFocus';

export interface PaletteEntry {
  group: string;
  label: string;
  icon: ReactElement | null;
  run: () => void;
}

interface CommandPaletteProps {
  entries: PaletteEntry[];
  returnFocusRef: RefObject<HTMLButtonElement | null>;
  onClose: () => void;
}

function matchEntries(entries: PaletteEntry[], filter: string): PaletteEntry[] {
  const needle = filter.trim().toLowerCase();
  if (!needle) return entries;
  return entries.filter((entry) => entry.label.toLowerCase().includes(needle));
}

function optionId(listId: string, index: number): string {
  return `${listId}-option-${index}`;
}

function PaletteList({ listId, matches, selected, onPick }: { listId: string; matches: PaletteEntry[]; selected: number; onPick: (entry: PaletteEntry) => void }) {
  let lastGroup = '';
  return (
    <div id={listId} className="cmdk-list" role="listbox" aria-label="Destinations and actions">
      {!matches.length ? <div className="cmdk-empty">No matching destination or action</div> : null}
      {matches.map((entry, index) => {
        const header = entry.group !== lastGroup ? <div className="cmdk-group" role="presentation">{entry.group}</div> : null;
        lastGroup = entry.group;
        const isSelected = index === selected;
        return (
          <Fragment key={`${entry.group}:${entry.label}`}>
            {header}
            <button
              type="button"
              id={optionId(listId, index)}
              role="option"
              aria-selected={isSelected}
              className={isSelected ? 'cmdk-item is-selected' : 'cmdk-item'}
              onClick={() => onPick(entry)}
            >
              <span className="tab-icon" aria-hidden="true">{entry.icon}</span>
              {entry.label}
              {isSelected ? <kbd>enter</kbd> : null}
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}

/**
 * Command palette ported from the legacy cmdkOpen()/cmdkRender(): substring
 * filter over nav destinations + actions, arrow-key selection with wraparound,
 * Enter runs, Esc or backdrop click closes. Styled by the shared .cmdk classes.
 */
export default function CommandPalette({ entries, returnFocusRef, onClose }: CommandPaletteProps) {
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState(0);
  const dialogRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  useModalFocus({ containerRef: dialogRef, initialFocusRef: inputRef, returnFocusRef, open: true, onDismiss: onClose });

  const matches = useMemo(() => matchEntries(entries, filter), [entries, filter]);
  const activeIndex = Math.min(selected, Math.max(0, matches.length - 1));

  const pick = (entry: PaletteEntry) => {
    onClose();
    entry.run();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      setSelected((activeIndex + step + matches.length) % Math.max(1, matches.length));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const entry = matches[activeIndex];
      if (entry) pick(entry);
    }
  };

  const onBackdrop = (event: MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) onClose();
  };

  return (
    <div className="cmdk-overlay" onMouseDown={onBackdrop}>
      <div ref={dialogRef} className="cmdk" role="dialog" aria-modal="true" aria-label="Command palette" tabIndex={-1}>
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          value={filter}
          placeholder="Jump to a tab or run an action"
          aria-label="Command palette filter"
          aria-autocomplete="list"
          aria-controls={listId}
          aria-expanded="true"
          aria-activedescendant={matches.length ? optionId(listId, activeIndex) : undefined}
          onChange={(event) => {
            setFilter(event.target.value);
            setSelected(0);
          }}
          onKeyDown={onKeyDown}
        />
        <PaletteList listId={listId} matches={matches} selected={activeIndex} onPick={pick} />
      </div>
    </div>
  );
}
