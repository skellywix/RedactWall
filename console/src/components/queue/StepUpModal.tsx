import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useModalFocus } from '../system/useModalFocus';

interface StepUpModalProps {
  title: string;
  message: string;
  confirmLabel: string;
  confirmClass: 'approve' | 'reveal';
  onConfirm: (password: string) => void;
  onCancel: () => void;
}

/**
 * Password step-up dialog, mirroring the legacy askStepUpPassword() modal.
 * The password lives only in local state and is handed to the caller once;
 * the component unmounts (and the state is dropped) right after.
 */
export function StepUpModal({
  title,
  message,
  confirmLabel,
  confirmClass,
  onConfirm,
  onCancel,
}: StepUpModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  const [password, setPassword] = useState('');

  // Register focus management before showModal() runs so the shared hook
  // captures the launcher, not the dialog's browser-selected autofocus field.
  useModalFocus({ containerRef: dialogRef, initialFocusRef: passwordRef, open: true, onDismiss: onCancel });

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) {
      dialog.showModal();
    }
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password) onConfirm(password);
  };

  return (
    <dialog
      ref={dialogRef}
      className="stepup-dialog"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      aria-modal="true"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <form className="stepup-panel" onSubmit={submit}>
        <div>
          <h2 id={titleId}>{title}</h2>
          <p id={descriptionId}>{message}</p>
        </div>
        <label>
          Account password
          <input
            ref={passwordRef}
            type="password"
            autoComplete="current-password"
            required
            autoFocus
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <div className="stepup-actions">
          <button className="btn" type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className={`btn ${confirmClass}`} type="submit">
            {confirmLabel}
          </button>
        </div>
      </form>
    </dialog>
  );
}
