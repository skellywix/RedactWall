/**
 * Non-blocking notices. Renders into the same #toastStack / .toast markup the
 * legacy console uses so console-theme.css styles apply unchanged, and stays
 * callable from non-React modules (the API client) without a context.
 */

export type ToastTone = 'info' | 'good' | 'warn' | 'error';

export function toast(message: string, tone: ToastTone = 'info'): void {
  let stack = document.getElementById('toastStack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toastStack';
    stack.setAttribute('aria-live', 'polite');
    document.body.appendChild(stack);
  }
  const el = document.createElement('div');
  el.className = `toast toast-${tone}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => {
    el.classList.add('gone');
    setTimeout(() => el.remove(), 300);
  }, 4200);
}
