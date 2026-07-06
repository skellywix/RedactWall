import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { applyColorTheme, savedColorTheme } from './lib/theme';
import './app.css';

// Apply the persisted color theme before first render. The document already
// paints dark by default (index.html); this switches to a stored 'light'
// choice with no persist write, mirroring the legacy dashboard.js startup.
applyColorTheme(savedColorTheme(), { persist: false });

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
