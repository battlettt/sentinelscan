import { Finding } from './types';

export interface CookieFlags {
  secure: boolean;
  sameSite: string | undefined;
}

export interface HeaderAnalysisInput {
  headers: Record<string, string>;
  isHttps: boolean;
  mixedContentUrls: string[];
  cookies: CookieFlags[];
}

export function analyzeHeaders(input: HeaderAnalysisInput): Finding[] {
  const findings: Finding[] = [];
  const h = input.headers;
  const csp = h['content-security-policy'];

  if (!csp) {
    findings.push({
      id: 'missing-csp',
      title: 'Missing Content-Security-Policy',
      description: 'No CSP header was found. Without one, injected scripts can execute freely if any XSS vector exists.',
      severity: 'high',
      category: 'header',
    });
  } else if (/unsafe-inline|unsafe-eval/.test(csp)) {
    findings.push({
      id: 'weak-csp',
      title: 'Weak Content-Security-Policy (unsafe-inline/unsafe-eval)',
      description: `CSP is present but allows ${csp.includes('unsafe-inline') ? "'unsafe-inline'" : "'unsafe-eval'"}, which defeats most of its XSS protection.`,
      severity: 'medium',
      category: 'header',
    });
  }

  if (!h['strict-transport-security']) {
    findings.push({
      id: 'missing-hsts',
      title: 'Missing Strict-Transport-Security',
      description: 'No HSTS header. Visitors can be downgraded to plain HTTP by a network attacker.',
      severity: 'medium',
      category: 'header',
    });
  }

  if (!h['x-frame-options'] && !/frame-ancestors/.test(csp || '')) {
    findings.push({
      id: 'missing-frame-protection',
      title: 'Missing X-Frame-Options / frame-ancestors',
      description: 'Page can be embedded in an iframe on another site, enabling clickjacking.',
      severity: 'medium',
      category: 'header',
    });
  }

  if (!h['x-content-type-options']) {
    findings.push({
      id: 'missing-content-type-options',
      title: 'Missing X-Content-Type-Options',
      description: 'Browsers may MIME-sniff responses, letting a non-script file be treated as executable script in some cases.',
      severity: 'low',
      category: 'header',
    });
  }

  if (!h['referrer-policy']) {
    findings.push({
      id: 'missing-referrer-policy',
      title: 'Missing Referrer-Policy',
      description: 'Full URLs (including query strings) may leak to third parties via the Referer header.',
      severity: 'low',
      category: 'header',
    });
  }

  if (!h['permissions-policy']) {
    findings.push({
      id: 'missing-permissions-policy',
      title: 'Missing Permissions-Policy',
      description: 'No policy restricting access to browser features like camera, microphone, or geolocation.',
      severity: 'info',
      category: 'header',
    });
  }

  if (input.isHttps && input.mixedContentUrls.length > 0) {
    findings.push({
      id: 'mixed-content',
      title: `Mixed content: ${input.mixedContentUrls.length} resource(s) loaded over HTTP`,
      description: 'An HTTPS page is loading some resources over plain HTTP, which can be tampered with in transit.',
      severity: 'high',
      category: 'header',
    });
  }

  if (input.cookies.some((c) => !c.secure)) {
    findings.push({
      id: 'cookie-missing-secure',
      title: 'Cookie missing Secure flag',
      description: 'A cookie can be sent over an unencrypted connection.',
      severity: 'medium',
      category: 'header',
    });
  }

  if (input.cookies.some((c) => !c.sameSite || c.sameSite.toLowerCase() === 'no_restriction')) {
    findings.push({
      id: 'cookie-missing-samesite',
      title: 'Cookie missing SameSite protection',
      description: 'A cookie can be sent along with cross-site requests, which can enable CSRF.',
      severity: 'medium',
      category: 'header',
    });
  }

  return findings;
}

const GRADE_THRESHOLDS: [number, string][] = [
  [95, 'A+'],
  [85, 'A'],
  [75, 'B+'],
  [65, 'B'],
  [55, 'B-'],
  [45, 'C'],
  [30, 'D'],
];

export function computeGrade(findings: Finding[]): string {
  const weights: Record<Finding['severity'], number> = { high: 25, medium: 12, low: 5, info: 2 };
  let score = 100;
  for (const f of findings) score -= weights[f.severity];
  score = Math.max(0, score);
  for (const [threshold, grade] of GRADE_THRESHOLDS) {
    if (score >= threshold) return grade;
  }
  return 'F';
}
