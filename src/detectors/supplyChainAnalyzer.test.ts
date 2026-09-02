import { describe, it, expect } from 'vitest';
import { analyzeSupplyChain, ScriptRef } from './supplyChainAnalyzer';

function script(overrides: Partial<ScriptRef> = {}): ScriptRef {
  return { url: 'https://cdn.example.com/lib.js', isCrossOrigin: true, hasIntegrity: false, ...overrides };
}

describe('analyzeSupplyChain', () => {
  it('flags a cross-origin script with no integrity attribute', () => {
    const findings = analyzeSupplyChain([script()]);
    expect(findings.some((f) => f.id === 'missing-sri')).toBe(true);
  });

  it('does not flag a cross-origin script that has an integrity attribute', () => {
    const findings = analyzeSupplyChain([script({ hasIntegrity: true })]);
    expect(findings).toHaveLength(0);
  });

  it('does not flag a same-origin script even without integrity', () => {
    const findings = analyzeSupplyChain([script({ isCrossOrigin: false })]);
    expect(findings).toHaveLength(0);
  });

  it('reports a single finding with a count, not one per script', () => {
    const findings = analyzeSupplyChain([script(), script({ url: 'https://other.example.com/b.js' })]);
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain('2');
  });

  it('produces no findings for an empty script list', () => {
    expect(analyzeSupplyChain([])).toEqual([]);
  });
});
