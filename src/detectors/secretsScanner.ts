import { Finding } from './types';

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
}

const KNOWN_PATTERNS: SecretPattern[] = [
  { id: 'secret-aws-access-key', name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { id: 'secret-stripe-secret-key', name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { id: 'secret-stripe-publishable-key', name: 'Stripe Publishable Key (live)', regex: /pk_live_[0-9a-zA-Z]{24,}/ },
  { id: 'secret-slack-token', name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/ },
  { id: 'secret-google-api-key', name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { id: 'secret-jwt', name: 'JSON Web Token', regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/ },
  { id: 'secret-private-key', name: 'Private Key Header', regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { id: 'secret-github-token', name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { id: 'secret-slack-webhook', name: 'Slack Incoming Webhook URL', regex: /hooks\.slack\.com\/services\/[A-Za-z0-9/]+/ },
];

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const ENTROPY_CANDIDATE = /['"`]([A-Za-z0-9+/_=-]{20,80})['"`]/g;
const ENTROPY_THRESHOLD = 4.0;

export function scanSourceForSecrets(source: string, sourceLabel: string): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of KNOWN_PATTERNS) {
    if (pattern.regex.test(source)) {
      findings.push({
        id: pattern.id,
        title: `Possible ${pattern.name} in ${sourceLabel}`,
        description: `A string matching the ${pattern.name} format was found in publicly served source.`,
        severity: 'high',
        category: 'secret',
      });
    }
  }

  let entropyHits = 0;
  const entropyRegex = new RegExp(ENTROPY_CANDIDATE);
  let match: RegExpExecArray | null;
  while ((match = entropyRegex.exec(source)) !== null) {
    if (shannonEntropy(match[1]) >= ENTROPY_THRESHOLD) entropyHits++;
  }

  if (entropyHits > 0) {
    findings.push({
      id: `secret-high-entropy-${sourceLabel}`,
      title: `${entropyHits} high-entropy string(s) in ${sourceLabel}`,
      description:
        'These strings look secret-shaped (high randomness) but did not match a known key format. Could be a token, or could be an id/hash — worth a manual look.',
      severity: 'medium',
      category: 'secret',
    });
  }

  return findings;
}
