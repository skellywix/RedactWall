import { useEffect, useRef, type ReactNode } from 'react';

interface PolicyDisclosureProps {
  section: string;
  title: string;
  description: string;
  meta?: ReactNode;
  tone?: 'default' | 'danger';
  children: ReactNode;
}

function requestedPolicySection(): string | null {
  const hash = window.location.hash.replace(/^#/, '');
  const queryStart = hash.indexOf('?');
  if (queryStart < 0) return null;
  return new URLSearchParams(hash.slice(queryStart + 1)).get('section');
}

/**
 * Native details/summary keeps keyboard and assistive-technology semantics.
 * A route such as #/policy?section=fleet opens the requested section without
 * consuming or rewriting any other route query parameters.
 */
export default function PolicyDisclosure({
  section,
  title,
  description,
  meta,
  tone = 'default',
  children,
}: PolicyDisclosureProps) {
  const details = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    const openRequestedSection = () => {
      if (requestedPolicySection() === section && details.current) details.current.open = true;
    };
    openRequestedSection();
    window.addEventListener('hashchange', openRequestedSection);
    return () => window.removeEventListener('hashchange', openRequestedSection);
  }, [section]);

  return (
    <details
      ref={details}
      id={`policy-${section}`}
      className={`policy-disclosure${tone === 'danger' ? ' danger' : ''}`}
      data-policy-section={section}
    >
      <summary>
        <span className="policy-disclosure-copy">
          <strong>{title}</strong>
          <span>{description}</span>
        </span>
        {meta ? <span className="policy-disclosure-meta">{meta}</span> : null}
        <span className="policy-disclosure-chevron" aria-hidden="true">⌄</span>
      </summary>
      <div className="policy-disclosure-body">{children}</div>
    </details>
  );
}
