import { useCallback, useState } from 'react';

/**
 * Color theme, ported verbatim from the legacy console (dashboard.js): a
 * `data-theme` attribute on <body>, values 'light' | 'dark', DARK by default,
 * persisted under the shared 'redactwall.theme' key so a choice made in either
 * console carries to the other. console-base.css + console-theme.css key every
 * token off body[data-theme=...]; documentElement.style.colorScheme is set too
 * so native controls and scrollbars match.
 */
export type ColorTheme = 'light' | 'dark';

const STORAGE_KEY = 'redactwall.theme';

export function normalizeColorTheme(value: string | null | undefined): ColorTheme {
  return value === 'light' ? 'light' : 'dark';
}

export function savedColorTheme(): ColorTheme {
  try {
    return normalizeColorTheme(localStorage.getItem(STORAGE_KEY));
  } catch {
    return 'dark';
  }
}

export function applyColorTheme(value: string, { persist = true }: { persist?: boolean } = {}): ColorTheme {
  const theme = normalizeColorTheme(value);
  document.body.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  if (persist) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* storage unavailable (private mode) — theme still applies for the session */
    }
  }
  return theme;
}

export function useColorTheme(): { theme: ColorTheme; setTheme: (value: ColorTheme) => void } {
  const [theme, setThemeState] = useState<ColorTheme>(savedColorTheme);
  const setTheme = useCallback((value: ColorTheme) => {
    setThemeState(applyColorTheme(value));
  }, []);
  return { theme, setTheme };
}
