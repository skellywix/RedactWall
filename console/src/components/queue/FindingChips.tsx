import type { QueryFinding } from '../../api/queries';

interface FindingChipsProps {
  findings?: QueryFinding[];
  categories?: string[];
}

/** Detection chips: typed findings with their masked values, then policy categories. */
export function FindingChips({ findings, categories }: FindingChipsProps) {
  const found = findings ?? [];
  const cats = categories ?? [];
  if (!found.length && !cats.length) return null;
  return (
    <div className="chips">
      {found.map((finding, index) => (
        <span
          className="chip"
          key={`${finding.type}:${index}`}
          title={`Detected type: ${finding.type}${finding.vendorLabel ? ` (${finding.vendorLabel})` : ''}`}
        >
          <b>{finding.type}</b>
          {finding.vendorLabel ? ` · ${finding.vendorLabel}` : ''} {finding.masked || 'redacted'}
        </span>
      ))}
      {cats.map((category) => (
        <span className="chip category" key={category} title={`Policy category: ${category}`}>
          <b>{category}</b>
        </span>
      ))}
    </div>
  );
}
