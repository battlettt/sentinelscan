import { Finding } from '../../detectors/types';

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  high: 'High',
  medium: 'Med',
  low: 'Low',
  info: 'Info',
};

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="finding-card">
      <div>
        <div className="finding-title">{finding.title}</div>
        {finding.attackTechniqueId && (
          <div className="finding-technique">
            {finding.attackTechniqueId} · {finding.attackTechniqueName}
          </div>
        )}
      </div>
      <span className={`severity-badge severity-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
    </div>
  );
}
