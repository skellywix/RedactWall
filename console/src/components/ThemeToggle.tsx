import type { ReactElement } from 'react';
import { useColorTheme } from '../lib/theme';

// Sun / moon glyphs, verbatim from the legacy theme toggle (index.html header).
const SUN = (
  <path
    d="M12 4V2m0 20v-2M4.93 4.93 3.51 3.51m16.98 16.98-1.42-1.42M4 12H2m20 0h-2M4.93 19.07l-1.42 1.42M20.49 3.51l-1.42 1.42M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z"
    stroke="currentColor"
    strokeWidth="1.7"
    strokeLinecap="round"
    strokeLinejoin="round"
  />
);
const MOON = (
  <path
    d="M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 7 7 0 1 0 20.5 15.5Z"
    stroke="currentColor"
    strokeWidth="1.7"
    strokeLinecap="round"
    strokeLinejoin="round"
  />
);

/** One named toggle exposes the action and avoids overlapping focus targets. */
export default function ThemeToggle(): ReactElement {
  const { theme, setTheme } = useColorTheme();
  const nextTheme = theme === 'dark' ? 'light' : 'dark';
  const label = `Switch to ${nextTheme} theme`;
  return (
    <div className="theme-toggle">
      <button
        type="button"
        data-theme-choice={nextTheme}
        title={label}
        aria-label={label}
        onClick={() => setTheme(nextTheme)}
      >
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          {nextTheme === 'light' ? SUN : MOON}
        </svg>
      </button>
    </div>
  );
}
