import { Fragment, useEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent, type ReactElement } from 'react';

export interface PaletteEntry {
  group: string;
  label: string;
  icon: ReactElement | null;
  run: () => void;
}

interface CommandPaletteProps {
  entries: PaletteEntry[];
  onClose: () => void;
}

function matchEntries(entries: PaletteEntry[], filter: string): PaletteEntry[] {
  const needle = filter.trim().toLowerCase();
  if (!needle) return entries;
  return entries.filter((entry) => entry.label.toLowerCase().includes(needle));
}

function PaletteList({ matches, selected, onPick }: { matches: PaletteEntry[]; selected: number; onPick: (entry: PaletteEntry) => void }) {
  let lastGroup = '';
  return (
    <div className="cmdk-list" role="listbox" aria-label="Destinations and actions">
      {!matches.length ? <div className="cmdk-empty">No matching destination or action</div> : null}
      {matches.map((entry, index) => {
        const header = entry.group !== lastGroup ? <div className="cmdk-group">{entry.group}</div> : null;
        lastGroup = entry.group;
        const isSelected = index === selected;
        return (
          <Fragment key={`${entry.group}:${entry.label}`}>
            {header}
            <button
              type="button"
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
export default function CommandPalette({ entries, onClose }: CommandPaletteProps) {
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const previous = document.activeElement;
    restoreRef.current = previous instanceof HTMLElement ? previous : null;
    inputRef.current?.focus();
    return () => restoreRef.current?.focus();
  }, []);

  const matches = useMemo(() => matchEntries(entries, filter), [entries, filter]);
  const activeIndex = Math.min(selected, Math.max(0, matches.length - 1));

  const pick = (entry: PaletteEntry) => {
    onClose();
    entry.run();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
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
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Command palette">
        <input
          ref={inputRef}
          type="text"
          value={filter}
          placeholder="Jump to a tab or run an action"
          aria-label="Command palette filter"
          onChange={(event) => {
            setFilter(event.target.value);
            setSelected(0);
          }}
          onKeyDown={onKeyDown}
        />
        <PaletteList matches={matches} selected={activeIndex} onPick={pick} />
      </div>
    </div>
  );
}
