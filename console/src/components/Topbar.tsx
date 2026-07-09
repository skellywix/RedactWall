import type { FocusEvent, MouseEvent, ReactElement } from 'react';
import type { LiveState } from '../lib/shell';
import LiveStatus from './LiveStatus';
import ThemeToggle from './ThemeToggle';

interface TopbarProps {
  who: string;
  liveState: LiveState;
  lastUpdated: string;
  onOpenPalette: () => void;
  onSignOut: () => void;
}

// Search + sign-out glyphs, verbatim from the legacy topbar (index.html).
const SEARCH_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m21 21-4.35-4.35M10.5 18a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15Z" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>
);
const LOGOUT_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10 6H6v12h4m4-3 3-3-3-3m3 3H9" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
);

export default function Topbar({ who, liveState, lastUpdated, onOpenPalette, onSignOut }: TopbarProps): ReactElement {
  // The input never keeps focus: blur before opening so closing the palette
  // cannot restore focus here and immediately re-open it.
  const openFromMouse = (event: MouseEvent<HTMLElement>) => {
    event.preventDefault();
    onOpenPalette();
  };
  const openFromFocus = (event: FocusEvent<HTMLInputElement>) => {
    event.currentTarget.blur();
    onOpenPalette();
  };

  return (
    <header className="app-topbar">
      <label className="search" htmlFor="globalSearch">
        {SEARCH_ICON}
        <input
          id="globalSearch"
          type="search"
          autoComplete="off"
          readOnly
          placeholder="Search FCU evidence or actions"
          aria-label="Open the command palette"
          onMouseDown={openFromMouse}
          onFocus={openFromFocus}
        />
        <kbd aria-hidden="true">Ctrl K</kbd>
      </label>
      <div className="spacer"></div>
      <LiveStatus state={liveState} lastUpdated={lastUpdated} />
      <ThemeToggle />
      <span className="who" id="who">{who}</span>
      <button className="ghost" id="logout" type="button" onClick={onSignOut}>
        {LOGOUT_ICON}
        Sign out
      </button>
    </header>
  );
}
