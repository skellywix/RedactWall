/**
 * Shared CSV export helpers. Centralized so the escaping — including the
 * spreadsheet formula-injection neutralization — cannot drift between the
 * Activity, Insights, Catalog, and Compliance exporters (CLAUDE.md no-duplication rule).
 */

/**
 * Quote a cell for CSV and neutralize spreadsheet formula injection: a value a
 * spreadsheet would evaluate (a leading =, +, -, @, tab, or CR) is prefixed with a
 * single quote so it renders as literal text instead of executing. Numbers are
 * emitted as-is — they carry no formula payload and must not gain a spurious
 * leading quote (which would also corrupt legitimate negative values).
 */
export function csvCell(value: string | number): string {
  if (typeof value === 'number') return String(value);
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

export function downloadCsv(name: string, lines: Array<Array<string | number>>): void {
  const body = lines.map((cells) => cells.map(csvCell).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob([body], { type: 'text/csv' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function csvStamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}
