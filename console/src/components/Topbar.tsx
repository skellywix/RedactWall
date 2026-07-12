import type { ReactElement, RefObject } from 'react';
import type { LiveState, PostureState } from '../lib/shell';
import LiveStatus from './LiveStatus';
import ThemeToggle from './ThemeToggle';

interface TopbarProps {
  who: string;
  liveState: LiveState;
  postureState: PostureState;
  lastUpdated: string;
  routeLabel: string;
  contextLabel: string;
  navOpen: boolean;
  menuButtonRef: RefObject<HTMLButtonElement | null>;
  paletteButtonRef: RefObject<HTMLButtonElement | null>;
  onOpenNav: () => void;
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
const MENU_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>
);

export default function Topbar({
  who,
  liveState,
  postureState,
  lastUpdated,
  routeLabel,
  contextLabel,
  navOpen,
  menuButtonRef,
  paletteButtonRef,
  onOpenNav,
  onOpenPalette,
  onSignOut,
}: TopbarProps): ReactElement {
  return (
    <header className="app-topbar">
      <button
        ref={menuButtonRef}
        className="app-menu-button ghost"
        type="button"
        aria-label="Open navigation menu"
        aria-controls="primary-navigation"
        aria-expanded={navOpen}
        onClick={onOpenNav}
      >
        {MENU_ICON}
      </button>
      <div className="app-route-context" aria-live="polite">
        <strong>{routeLabel}</strong>
        <span>{contextLabel}</span>
      </div>
      <button
        ref={paletteButtonRef}
        className="search app-palette-launcher"
        id="globalSearch"
        type="button"
        aria-label="Open the command palette"
        aria-keyshortcuts="Control+K Meta+K"
        onClick={onOpenPalette}
      >
        {SEARCH_ICON}
        <span>Search FCU evidence or actions</span>
        <kbd aria-hidden="true">Ctrl K</kbd>
      </button>
      <div className="spacer"></div>
      <LiveStatus state={liveState} postureState={postureState} lastUpdated={lastUpdated} />
      <ThemeToggle />
      <span className="who" id="who" title={who}>{who}</span>
      <button className="ghost" id="logout" type="button" onClick={onSignOut}>
        {LOGOUT_ICON}
        <span>Sign out</span>
      </button>
    </header>
  );
}
