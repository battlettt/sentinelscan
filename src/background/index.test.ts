import { describe, it, expect } from 'vitest';
import { shortLabel } from './index';

describe('shortLabel', () => {
  it('returns just the filename portion of a URL', () => {
    expect(shortLabel('https://cdn.example.com/assets/bundle.a1b2.js')).toBe('bundle.a1b2.js');
  });

  it('returns the whole string when there is no slash', () => {
    expect(shortLabel('bundle.js')).toBe('bundle.js');
  });
});
