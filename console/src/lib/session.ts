import { useEffect, useState } from 'react';
import { apiJson } from './api';

export interface Me {
  user: string;
  role: string;
  authProvider: string;
  defaultPassword: boolean;
}

const ROLE_LABELS: Record<string, string> = {
  security_admin: 'Global Administrator',
  approver: 'Member Data Reviewer',
  operator: 'Operations Administrator',
  auditor: 'Read-only Examiner/Auditor',
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role] || role;
}

export function useSession(): { me: Me | null; loading: boolean } {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    apiJson<Me>('/api/me').then((body) => {
      if (cancelled) return;
      setMe(body);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return { me, loading };
}
