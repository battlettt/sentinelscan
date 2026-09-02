import { describe, it, expect } from 'vitest';
import { scanSourceForSecrets } from './secretsScanner';

describe('scanSourceForSecrets', () => {
  it('detects an AWS access key pattern', () => {
    const source = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings.some((f) => f.id === 'secret-aws-access-key')).toBe(true);
  });

  it('detects a Stripe live secret key pattern', () => {
    const source = `stripe.init("sk_live_${'a'.repeat(30)}");`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings.some((f) => f.id === 'secret-stripe-secret-key')).toBe(true);
  });

  it('detects a GitHub personal access token pattern', () => {
    const source = `const token = "ghp_${'a'.repeat(36)}";`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings.some((f) => f.id === 'secret-github-token')).toBe(true);
  });

  it('detects a Slack incoming webhook URL', () => {
    // Deliberately not shaped like a real Slack webhook ID (T.../B.../...) so this
    // fixture doesn't trip GitHub's own push-protection secret scanner — it only
    // needs to match our broad path-based regex, not look like a genuine webhook.
    const source = `fetch("https://hooks.slack.com/services/not-a-real-webhook-path")`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings.some((f) => f.id === 'secret-slack-webhook')).toBe(true);
  });

  it('flags a high-entropy string with no known pattern match', () => {
    const source = `const token = "Kj8vQzT2pLmN9xRbYcWdEfGhIjKlMnOp";`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings.some((f) => f.id.startsWith('secret-high-entropy'))).toBe(true);
  });

  it('produces no findings for ordinary source with no secrets', () => {
    const source = `function add(a, b) { return a + b; } console.log("hello world");`;
    const findings = scanSourceForSecrets(source, 'bundle.js');
    expect(findings).toHaveLength(0);
  });
});
