import { describe, it, expect } from 'vitest';
import { getFixSnippet } from './fixSnippets';

describe('getFixSnippet', () => {
  it('returns Express and Nginx snippets for a known finding id', () => {
    const snippet = getFixSnippet('missing-csp');
    expect(snippet).toBeDefined();
    expect(snippet?.express).toContain('Content-Security-Policy');
    expect(snippet?.nginx).toContain('Content-Security-Policy');
  });

  it('returns undefined for a finding id with no known fix', () => {
    expect(getFixSnippet('missing-sri')).toBeUndefined();
  });
});
