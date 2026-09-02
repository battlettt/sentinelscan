import { describe, it, expect } from 'vitest';
import { detectDrift } from './driftDetector';
import { ScanSnapshot } from './types';

function snapshot(overrides: Partial<ScanSnapshot> = {}): ScanSnapshot {
  return {
    domain: 'example.com',
    timestamp: 1000,
    headerFlags: { csp: true, hsts: true },
    cookieFlags: { secure: true, sameSite: true },
    secretsCount: 0,
    sriMissingCount: 0,
    grade: 'A',
    ...overrides,
  };
}

describe('detectDrift', () => {
  it('returns no findings when there is no previous snapshot', () => {
    expect(detectDrift(snapshot(), null)).toEqual([]);
  });

  it('flags a header that was present and is now missing', () => {
    const previous = snapshot({ headerFlags: { csp: true } });
    const current = snapshot({ headerFlags: { csp: false } });
    const findings = detectDrift(current, previous);
    expect(findings.some((f) => f.id === 'drift-lost-csp')).toBe(true);
  });

  it('flags an increase in secrets count', () => {
    const previous = snapshot({ secretsCount: 0 });
    const current = snapshot({ secretsCount: 2 });
    const findings = detectDrift(current, previous);
    expect(findings.some((f) => f.id === 'drift-new-secrets')).toBe(true);
  });

  it('flags an increase in scripts missing SRI', () => {
    const previous = snapshot({ sriMissingCount: 0 });
    const current = snapshot({ sriMissingCount: 1 });
    const findings = detectDrift(current, previous);
    expect(findings.some((f) => f.id === 'drift-new-sri-gaps')).toBe(true);
  });

  it('flags a grade drop', () => {
    const previous = snapshot({ grade: 'A' });
    const current = snapshot({ grade: 'C' });
    const findings = detectDrift(current, previous);
    expect(findings.some((f) => f.id === 'drift-grade-drop')).toBe(true);
  });

  it('does not flag a grade improvement as a drop', () => {
    const previous = snapshot({ grade: 'C' });
    const current = snapshot({ grade: 'A' });
    const findings = detectDrift(current, previous);
    expect(findings.some((f) => f.id === 'drift-grade-drop')).toBe(false);
  });

  it('returns no findings for two identical snapshots', () => {
    const s = snapshot();
    expect(detectDrift(s, s)).toEqual([]);
  });
});
