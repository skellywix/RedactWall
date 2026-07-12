import { useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    const style = window.getComputedStyle(element);
    return !element.hidden && style.display !== 'none' && style.visibility !== 'hidden';
  });
}

interface ModalFocusOptions {
  containerRef: RefObject<HTMLElement | null>;
  initialFocusRef?: RefObject<HTMLElement | null>;
  returnFocusRef?: RefObject<HTMLElement | null>;
  open: boolean;
  onDismiss: () => void;
}

const modalStack: symbol[] = [];
let scrollLockCount = 0;
let unlockedOverflow = '';

function lockDocumentScroll(): void {
  if (scrollLockCount === 0) unlockedOverflow = document.body.style.overflow;
  scrollLockCount += 1;
  document.body.style.overflow = 'hidden';
}

function unlockDocumentScroll(): void {
  scrollLockCount = Math.max(0, scrollLockCount - 1);
  if (scrollLockCount === 0) document.body.style.overflow = unlockedOverflow;
}

/**
 * Keeps keyboard focus inside an open modal surface, closes it with Escape,
 * prevents background scrolling, and returns focus to the launcher on close.
 */
export function useModalFocus({ containerRef, initialFocusRef, returnFocusRef, open, onDismiss }: ModalFocusOptions): void {
  const dismissRef = useRef(onDismiss);
  dismissRef.current = onDismiss;

  useEffect(() => {
    if (!open) return;

    const container = containerRef.current;
    if (!container) return;

    const token = Symbol('modal-focus');
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    modalStack.push(token);
    lockDocumentScroll();
    const isTopModal = () => modalStack[modalStack.length - 1] === token;

    const focusFirst = () => {
      const target = initialFocusRef?.current ?? focusableElements(container)[0] ?? container;
      target.focus({ preventScroll: true });
    };

    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (!isTopModal()) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        dismissRef.current();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = focusableElements(container);
      if (!focusable.length) {
        event.preventDefault();
        container.focus({ preventScroll: true });
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !container.contains(active))) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    };

    const onFocusIn = (event: FocusEvent) => {
      if (isTopModal() && event.target instanceof Node && !container.contains(event.target)) focusFirst();
    };

    const focusFrame = window.requestAnimationFrame(() => {
      if (isTopModal()) focusFirst();
    });
    document.addEventListener('keydown', onKeyDown, true);
    document.addEventListener('focusin', onFocusIn, true);

    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener('keydown', onKeyDown, true);
      document.removeEventListener('focusin', onFocusIn, true);
      const wasTopModal = isTopModal();
      const stackIndex = modalStack.lastIndexOf(token);
      if (stackIndex >= 0) modalStack.splice(stackIndex, 1);
      unlockDocumentScroll();
      const returnTarget = returnFocusRef?.current ?? previousFocus;
      if (wasTopModal && returnTarget?.isConnected) {
        // Backdrop dismissal starts on mousedown. Restore on the next frame so
        // the remainder of that pointer click cannot clear the launcher's
        // focus, while still refusing to steal focus from a newer modal.
        const remainingTop = modalStack[modalStack.length - 1];
        window.requestAnimationFrame(() => {
          if (modalStack[modalStack.length - 1] === remainingTop && returnTarget.isConnected) {
            returnTarget.focus({ preventScroll: true });
          }
        });
      }
    };
  }, [containerRef, initialFocusRef, open, returnFocusRef]);
}
