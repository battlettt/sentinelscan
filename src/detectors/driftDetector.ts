import { Finding, ScanSnapshot } from './types';

const GRADE_ORDER = ['F', 'D', 'C', 'B-', 'B', 'B+', 'A', 'A+'];

function gradeRank(grade: string): number {
  const idx = GRADE_ORDER.indexOf(grade);
  return idx === -1 ? 0 : idx;
}

function formatDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}

export function detectDrift(current: ScanSnapshot, previous: ScanSnapshot | null): Finding[] {
  if (!previous) return [];
  const findings: Finding[] = [];

  for (const key of Object.keys(previous.headerFlags)) {
    if (previous.headerFlags[key] && !current.headerFlags[key]) {
      findings.push({
        id: `drift-lost-${key}`,
        title: `${key} was present on ${formatDate(previous.timestamp)}, missing today`,
        description: 'This header/protection was present on the last scan and is no longer being sent.',
        severity: 'medium',
        category: 'drift',
      });
    }
  }

  if (current.secretsCount > previous.secretsCount) {
    findings.push({
      id: 'drift-new-secrets',
      title: `${current.secretsCount - previous.secretsCount} new possible secret(s) since last scan`,
      description: `Secrets scan found more matches than the last scan on ${formatDate(previous.timestamp)}.`,
      severity: 'high',
      category: 'drift',
    });
  }

  if (gradeRank(current.grade) < gradeRank(previous.grade)) {
    findings.push({
      id: 'drift-grade-drop',
      title: `Grade dropped from ${previous.grade} to ${current.grade}`,
      description: `Overall security grade is lower than the last scan on ${formatDate(previous.timestamp)}.`,
      severity: 'medium',
      category: 'drift',
    });
  }

  return findings;
}
