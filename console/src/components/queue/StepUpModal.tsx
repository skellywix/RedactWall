import { useEffect, useRef, useState, type FormEvent } from 'react';

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
export function StepUpModal({ title, message, confirmLabel, confirmClass, onConfirm, onCancel }: StepUpModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [password, setPassword] = useState('');

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password) onConfirm(password);
  };

  return (
    <dialog
      ref={dialogRef}
      className="stepup-dialog"
      aria-label={title}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <form className="stepup-panel" onSubmit={submit}>
        <div>
          <h2>{title}</h2>
          <p>{message}</p>
        </div>
        <label>
          Account password
          <input
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
