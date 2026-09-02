import { describe, it, expect } from 'vitest';
import { analyzeHeaders, computeGrade } from './headerAnalyzer';

describe('analyzeHeaders', () => {
  it('flags a missing CSP as high severity', () => {
    const findings = analyzeHeaders({
      headers: {},
      isHttps: true,
      mixedContentUrls: [],
      cookies: [],
    });
    const csp = findings.find((f) => f.id === 'missing-csp');
    expect(csp).toBeDefined();
    expect(csp?.severity).toBe('high');
  });

  it('flags a CSP with unsafe-inline as weak, not missing', () => {
    const findings = analyzeHeaders({
      headers: { 'content-security-policy': "default-src 'self' 'unsafe-inline'" },
      isHttps: true,
      mixedContentUrls: [],
      cookies: [],
    });
    expect(findings.find((f) => f.id === 'missing-csp')).toBeUndefined();
    expect(findings.find((f) => f.id === 'weak-csp')).toBeDefined();
  });

  it('produces no header findings when everything is present and strong', () => {
    const findings = analyzeHeaders({
      headers: {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=63072000',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
      },
      isHttps: true,
      mixedContentUrls: [],
      cookies: [{ secure: true, sameSite: 'strict' }],
    });
    expect(findings).toHaveLength(0);
  });

  it('flags mixed content on an https page', () => {
    const findings = analyzeHeaders({
      headers: { 'content-security-policy': "default-src 'self'" },
      isHttps: true,
      mixedContentUrls: ['http://insecure.example.com/a.js'],
      cookies: [],
    });
    expect(findings.find((f) => f.id === 'mixed-content')).toBeDefined();
  });

  it('flags a cookie missing the Secure flag', () => {
    const findings = analyzeHeaders({
      headers: {},
      isHttps: true,
      mixedContentUrls: [],
      cookies: [{ secure: false, sameSite: 'lax' }],
    });
    expect(findings.find((f) => f.id === 'cookie-missing-secure')).toBeDefined();
  });
});

describe('computeGrade', () => {
  it('returns A+ for zero findings', () => {
    expect(computeGrade([])).toBe('A+');
  });

  it('returns F when total deductions exceed 100', () => {
    const highs = Array.from({ length: 5 }, (_, i) => ({
      id: `h${i}`,
      title: 'x',
      description: 'x',
      severity: 'high' as const,
      category: 'header' as const,
    }));
    expect(computeGrade(highs)).toBe('F');
  });
});
