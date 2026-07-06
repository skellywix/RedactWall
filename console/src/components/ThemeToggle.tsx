import type { ReactElement } from 'react';
import { useColorTheme, type ColorTheme } from '../lib/theme';

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

const CHOICES: { value: ColorTheme; label: string; icon: ReactElement }[] = [
  { value: 'light', label: 'Switch to light', icon: SUN },
  { value: 'dark', label: 'Switch to dark', icon: MOON },
];

/** Segmented light/dark control. Styled by `.theme-toggle` in console-base.css. */
export default function ThemeToggle(): ReactElement {
  const { theme, setTheme } = useColorTheme();
  return (
    <div className="theme-toggle" role="group" aria-label="Color theme">
      {CHOICES.map((choice) => {
        const selected = theme === choice.value;
        return (
          <button
            key={choice.value}
            type="button"
            data-theme-choice={choice.value}
            className={selected ? 'active' : ''}
            aria-pressed={selected}
            title={choice.label}
            aria-label={choice.label}
            onClick={() => setTheme(choice.value)}
          >
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              {choice.icon}
            </svg>
          </button>
        );
      })}
    </div>
  );
}
