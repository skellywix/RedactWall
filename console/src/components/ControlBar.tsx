interface ControlBarProps {
  label: string;
  score: number;
  detail: string;
  value: string | number;
  tone: 'secure' | 'critical' | 'warn';
}

/** Score row with a proportional bar; mirrors the legacy .control-row markup. */
export function ControlBar({ label, score, detail, value, tone }: ControlBarProps) {
  const width = Math.max(5, Math.min(100, Number(score) || 0));
  return (
    <div className="control-row">
      <div>
        <strong>{label}</strong>
        <span>
          {value} / {score || 0}/100
        </span>
      </div>
      <div className="control-bar" role="img" aria-label={`${label} ${score || 0} out of 100`}>
        <i className={`tone-${tone}`} style={{ '--w': `${width}%` } as React.CSSProperties} />
      </div>
      <span>{detail}</span>
    </div>
  );
}

export function stateTone(state: string): 'secure' | 'critical' | 'warn' {
  if (state === 'ready') return 'secure';
  if (state === 'blocked') return 'critical';
  return 'warn';
}
