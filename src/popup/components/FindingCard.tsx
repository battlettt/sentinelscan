import { useState } from 'react';
import { Finding } from '../../detectors/types';
import { getFixSnippet } from '../../detectors/fixSnippets';

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  high: 'High',
  medium: 'Med',
  low: 'Low',
  info: 'Info',
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const snippet = getFixSnippet(finding.id);

  return (
    <div className="finding-card-wrap">
      <div
        className="finding-card"
        onClick={snippet ? () => setExpanded((v) => !v) : undefined}
        style={snippet ? { cursor: 'pointer' } : undefined}
      >
        <div>
          <div className="finding-title">{finding.title}</div>
          {finding.attackTechniqueId && (
            <div className="finding-technique">
              {finding.attackTechniqueId} · {finding.attackTechniqueName}
            </div>
          )}
          {snippet && <div className="finding-fix-toggle">{expanded ? 'Hide fix' : 'Show fix'}</div>}
        </div>
        <span className={`severity-badge severity-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
      </div>

      {expanded && snippet && (
        <div className="fix-snippet">
          <div className="fix-snippet-label">Express</div>
          <pre>{snippet.express}</pre>
          <div className="fix-snippet-label">Nginx</div>
          <pre>{snippet.nginx}</pre>
        </div>
      )}
    </div>
  );
}
