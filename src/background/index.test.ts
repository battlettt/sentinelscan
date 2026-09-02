import { describe, it, expect } from 'vitest';
import { extractScriptUrls, shortLabel } from './index';

describe('extractScriptUrls', () => {
  it('extracts absolute and relative script src URLs', () => {
    const html = `
      <script src="https://cdn.example.com/a.js"></script>
      <script src="/local/b.js"></script>
      <script>console.log('inline, ignored')</script>
    `;
    const urls = extractScriptUrls(html, 'https://example.com/page');
    expect(urls).toEqual(['https://cdn.example.com/a.js', 'https://example.com/local/b.js']);
  });

  it('ignores a malformed absolute src attribute instead of throwing', () => {
    // A relative-looking string resolves fine against a base (WHATWG URL is lenient there);
    // an absolute URL with a space in the host is what actually fails to parse.
    const html = `<script src="http://bad host/x.js"></script>`;
    expect(() => extractScriptUrls(html, 'https://example.com/')).not.toThrow();
    expect(extractScriptUrls(html, 'https://example.com/')).toEqual([]);
  });
});

describe('shortLabel', () => {
  it('returns just the filename portion of a URL', () => {
    expect(shortLabel('https://cdn.example.com/assets/bundle.a1b2.js')).toBe('bundle.a1b2.js');
  });
});
