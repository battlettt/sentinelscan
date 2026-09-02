# SentinelScan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build v1 of SentinelScan — a Manifest V3 Chrome extension that scans the active tab on click for header/config issues and exposed secrets, maps findings to MITRE ATT&CK techniques, and flags drift against the domain's last scan, all stored locally.

**Architecture:** React + TypeScript popup sends a scan request to a background service worker. The service worker re-fetches the page (to read response headers), fetches linked scripts (secrets scan), reads cookie flags (`chrome.cookies`), and reads/writes per-domain scan history in `chrome.storage.local`. Pure detection logic (header analysis, secrets scanning, ATT&CK mapping, drift diffing) lives in framework-free, independently-testable modules.

**Tech Stack:** TypeScript, React 18, Vite (build + bundling), Vitest (testing), Manifest V3, `activeTab` + `cookies` + `storage` permissions only — no `<all_urls>`.

**Deviation from the design spec to note:** the spec described header capture "via webRequest." In MV3, `webRequest` observation doesn't cleanly attach to a scan triggered by a button click on an already-loaded page. This plan instead has the background service worker re-fetch the current URL directly and read `response.headers` from that fetch — same passive, local-only result, simpler and more reliable under MV3's service-worker model.

---

## File Structure

```
sentinelscan/
├── manifest.json
├── package.json
├── tsconfig.json
├── vite.config.ts
├── scripts/
│   └── generate-icons.cjs
├── src/
│   ├── icons/                      (generated, gitignored placeholder PNGs)
│   ├── detectors/
│   │   ├── types.ts
│   │   ├── headerAnalyzer.ts
│   │   ├── headerAnalyzer.test.ts
│   │   ├── secretsScanner.ts
│   │   ├── secretsScanner.test.ts
│   │   ├── attackMapper.ts
│   │   ├── attackMapper.test.ts
│   │   ├── driftDetector.ts
│   │   └── driftDetector.test.ts
│   ├── storage/
│   │   ├── historyStore.ts
│   │   └── historyStore.test.ts
│   ├── background/
│   │   ├── index.ts
│   │   └── index.test.ts
│   └── popup/
│       ├── popup.html
│       ├── main.tsx
│       ├── App.tsx
│       ├── Popup.css
│       └── components/
│           ├── GradeRing.tsx
│           └── FindingCard.tsx
```

---

## Task 1: Project scaffold & tooling

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vite.config.ts`
- Create: `manifest.json`
- Modify: `.gitignore`

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "sentinelscan",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite build --watch",
    "build": "node scripts/generate-icons.cjs && vite build",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@types/chrome": "^0.0.269",
    "@types/react": "^18.3.3",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "typescript": "^5.5.4",
    "vite": "^5.4.1",
    "vite-plugin-static-copy": "^1.0.6",
    "vitest": "^2.0.5"
  }
}
```

- [ ] **Step 2: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "types": ["chrome", "vitest/globals"]
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Write `vite.config.ts`**

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteStaticCopy } from 'vite-plugin-static-copy';
import { resolve } from 'path';

export default defineConfig({
  plugins: [
    react(),
    viteStaticCopy({
      targets: [
        { src: 'manifest.json', dest: '.' },
        { src: 'src/icons', dest: '.' },
      ],
    }),
  ],
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        background: resolve(__dirname, 'src/background/index.ts'),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js',
      },
    },
  },
});
```

- [ ] **Step 4: Write `manifest.json`**

```json
{
  "manifest_version": 3,
  "name": "SentinelScan",
  "version": "0.1.0",
  "description": "A real security report card for any website: header/config analysis, secrets scanning, and drift detection over time. Runs entirely locally.",
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "background": {
    "service_worker": "background.js"
  },
  "permissions": ["activeTab", "cookies", "storage"],
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}
```

- [ ] **Step 5: Add build output and icons to `.gitignore`**

Append to the existing `.gitignore`:

```
dist/
node_modules/
src/icons/*.png
```

- [ ] **Step 6: Install dependencies**

Run: `cd ~/Downloads/extension-project && npm install`
Expected: installs with no errors, creates `node_modules/` and `package-lock.json`

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json tsconfig.json vite.config.ts manifest.json .gitignore
git commit -m "chore: scaffold Vite + TypeScript + React extension project"
```

---

## Task 2: Shared types + placeholder icons

**Files:**
- Create: `src/detectors/types.ts`
- Create: `scripts/generate-icons.cjs`

- [ ] **Step 1: Write `src/detectors/types.ts`**

```typescript
export type Severity = 'high' | 'medium' | 'low' | 'info';
export type FindingCategory = 'header' | 'secret' | 'drift';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  attackTechniqueId?: string;
  attackTechniqueName?: string;
}

export interface ScanSnapshot {
  domain: string;
  timestamp: number;
  headerFlags: Record<string, boolean>;
  cookieFlags: { secure: boolean; sameSite: boolean };
  secretsCount: number;
  grade: string;
}

export interface ScanResult {
  domain: string;
  timestamp: number;
  grade: string;
  findings: Finding[];
  driftFindings: Finding[];
  scannedScriptCount: number;
  skippedScriptCount: number;
}
```

- [ ] **Step 2: Write `scripts/generate-icons.cjs`**

Zero-dependency PNG encoder (writes a raw solid-color PNG using Node's built-in `zlib`) — no image library needed for placeholder icons.

```javascript
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

function crc32(buf) {
  const table = crc32.table || (crc32.table = (() => {
    const t = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c;
    }
    return t;
  })());
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function makeSolidPng(size, [r, g, b]) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const rowLength = size * 3 + 1;
  const raw = Buffer.alloc(rowLength * size);
  for (let y = 0; y < size; y++) {
    const rowStart = y * rowLength;
    raw[rowStart] = 0;
    for (let x = 0; x < size; x++) {
      const px = rowStart + 1 + x * 3;
      raw[px] = r;
      raw[px + 1] = g;
      raw[px + 2] = b;
    }
  }
  const idatData = zlib.deflateSync(raw);
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([signature, chunk('IHDR', ihdr), chunk('IDAT', idatData), chunk('IEND', Buffer.alloc(0))]);
}

const outDir = path.join(__dirname, '..', 'src', 'icons');
fs.mkdirSync(outDir, { recursive: true });

const GREEN = [34, 197, 94];
for (const size of [16, 48, 128]) {
  fs.writeFileSync(path.join(outDir, `icon${size}.png`), makeSolidPng(size, GREEN));
}
console.log('Generated placeholder icons in src/icons/');
```

Note in the generated icons' commit/PR description: these are flat-color placeholders, not final branding — swap before Chrome Web Store submission.

- [ ] **Step 3: Run the icon generator**

Run: `node scripts/generate-icons.cjs`
Expected: `Generated placeholder icons in src/icons/`, and `src/icons/icon16.png`, `icon48.png`, `icon128.png` exist

- [ ] **Step 4: Commit**

```bash
git add src/detectors/types.ts scripts/generate-icons.cjs
git commit -m "feat: add shared Finding/ScanResult types and icon generator"
```

---

## Task 3: Header/Config Analyzer

**Files:**
- Create: `src/detectors/headerAnalyzer.ts`
- Test: `src/detectors/headerAnalyzer.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/detectors/headerAnalyzer.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/detectors/headerAnalyzer.test.ts`
Expected: FAIL — `Cannot find module './headerAnalyzer'`

- [ ] **Step 3: Write `src/detectors/headerAnalyzer.ts`**

```typescript
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
  [95, 'A+'], [85, 'A'], [75, 'B+'], [65, 'B'], [55, 'B-'], [45, 'C'], [30, 'D'],
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/detectors/headerAnalyzer.test.ts`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/detectors/headerAnalyzer.ts src/detectors/headerAnalyzer.test.ts
git commit -m "feat: add header/config analyzer with grade calculation"
```

---

## Task 4: Secrets Scanner

**Files:**
- Create: `src/detectors/secretsScanner.ts`
- Test: `src/detectors/secretsScanner.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/detectors/secretsScanner.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/detectors/secretsScanner.test.ts`
Expected: FAIL — `Cannot find module './secretsScanner'`

- [ ] **Step 3: Write `src/detectors/secretsScanner.ts`**

```typescript
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
      description: 'These strings look secret-shaped (high randomness) but did not match a known key format. Could be a token, or could be an id/hash — worth a manual look.',
      severity: 'medium',
      category: 'secret',
    });
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/detectors/secretsScanner.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/detectors/secretsScanner.ts src/detectors/secretsScanner.test.ts
git commit -m "feat: add secrets scanner (known patterns + entropy detection)"
```

---

## Task 5: ATT&CK Mapper

**Files:**
- Create: `src/detectors/attackMapper.ts`
- Test: `src/detectors/attackMapper.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/detectors/attackMapper.test.ts
import { describe, it, expect } from 'vitest';
import { applyAttackMappings } from './attackMapper';
import { Finding } from './types';

function baseFinding(id: string): Finding {
  return { id, title: 't', description: 'd', severity: 'medium', category: 'header' };
}

describe('applyAttackMappings', () => {
  it('attaches a technique to a known finding id', () => {
    const [result] = applyAttackMappings([baseFinding('missing-csp')]);
    expect(result.attackTechniqueId).toBe('T1189');
    expect(result.attackTechniqueName).toBe('Drive-by Compromise');
  });

  it('leaves an unmapped finding id unchanged', () => {
    const [result] = applyAttackMappings([baseFinding('missing-permissions-policy')]);
    expect(result.attackTechniqueId).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/detectors/attackMapper.test.ts`
Expected: FAIL — `Cannot find module './attackMapper'`

- [ ] **Step 3: Write `src/detectors/attackMapper.ts`**

```typescript
import { Finding } from './types';

interface AttackMapping {
  techniqueId: string;
  techniqueName: string;
}

const FINDING_TO_ATTACK: Record<string, AttackMapping> = {
  'missing-csp': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'weak-csp': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'missing-content-type-options': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'missing-hsts': { techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle' },
  'mixed-content': { techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle' },
  'missing-frame-protection': { techniqueId: 'T1185', techniqueName: 'Browser Session Hijacking' },
  'cookie-missing-samesite': { techniqueId: 'T1185', techniqueName: 'Browser Session Hijacking' },
};

export function applyAttackMappings(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    const mapping = FINDING_TO_ATTACK[f.id];
    return mapping ? { ...f, attackTechniqueId: mapping.techniqueId, attackTechniqueName: mapping.techniqueName } : f;
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/detectors/attackMapper.test.ts`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/detectors/attackMapper.ts src/detectors/attackMapper.test.ts
git commit -m "feat: add MITRE ATT&CK mapping table for findings"
```

---

## Task 6: History Store

**Files:**
- Create: `src/storage/historyStore.ts`
- Test: `src/storage/historyStore.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/storage/historyStore.test.ts
import { describe, it, expect } from 'vitest';
import { HistoryStore, KeyValueStorage } from './historyStore';
import { ScanSnapshot } from '../detectors/types';

class InMemoryStorage implements KeyValueStorage {
  private map = new Map<string, unknown>();
  async get(key: string) {
    return this.map.get(key);
  }
  async set(key: string, value: unknown) {
    this.map.set(key, value);
  }
}

function snapshot(domain: string, timestamp: number, grade = 'A'): ScanSnapshot {
  return {
    domain,
    timestamp,
    headerFlags: {},
    cookieFlags: { secure: true, sameSite: true },
    secretsCount: 0,
    grade,
  };
}

describe('HistoryStore', () => {
  it('returns an empty history for a domain with no scans', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    expect(await store.getHistory('example.com')).toEqual([]);
    expect(await store.getLatest('example.com')).toBeNull();
  });

  it('appends a snapshot and returns it as the latest', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    await store.appendSnapshot('example.com', snapshot('example.com', 1000));
    const latest = await store.getLatest('example.com');
    expect(latest?.timestamp).toBe(1000);
  });

  it('trims history beyond 20 entries per domain', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    for (let i = 0; i < 25; i++) {
      await store.appendSnapshot('example.com', snapshot('example.com', i));
    }
    const history = await store.getHistory('example.com');
    expect(history).toHaveLength(20);
    expect(history[0].timestamp).toBe(5);
    expect(history[19].timestamp).toBe(24);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/storage/historyStore.test.ts`
Expected: FAIL — `Cannot find module './historyStore'`

- [ ] **Step 3: Write `src/storage/historyStore.ts`**

```typescript
import { ScanSnapshot } from '../detectors/types';

export interface KeyValueStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
}

export class ChromeLocalStorage implements KeyValueStorage {
  get(key: string): Promise<unknown> {
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => resolve(result[key]));
    });
  }
  set(key: string, value: unknown): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: value }, () => resolve());
    });
  }
}

const MAX_HISTORY_PER_DOMAIN = 20;

export class HistoryStore {
  constructor(private storage: KeyValueStorage) {}

  private keyFor(domain: string): string {
    return `history:${domain}`;
  }

  async getHistory(domain: string): Promise<ScanSnapshot[]> {
    const raw = await this.storage.get(this.keyFor(domain));
    return Array.isArray(raw) ? (raw as ScanSnapshot[]) : [];
  }

  async getLatest(domain: string): Promise<ScanSnapshot | null> {
    const history = await this.getHistory(domain);
    return history.length > 0 ? history[history.length - 1] : null;
  }

  async appendSnapshot(domain: string, snapshot: ScanSnapshot): Promise<void> {
    const history = await this.getHistory(domain);
    history.push(snapshot);
    while (history.length > MAX_HISTORY_PER_DOMAIN) history.shift();
    await this.storage.set(this.keyFor(domain), history);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/storage/historyStore.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/storage/historyStore.ts src/storage/historyStore.test.ts
git commit -m "feat: add per-domain scan history store over chrome.storage.local"
```

---

## Task 7: Drift Detector

**Files:**
- Create: `src/detectors/driftDetector.ts`
- Test: `src/detectors/driftDetector.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/detectors/driftDetector.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/detectors/driftDetector.test.ts`
Expected: FAIL — `Cannot find module './driftDetector'`

- [ ] **Step 3: Write `src/detectors/driftDetector.ts`**

```typescript
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/detectors/driftDetector.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/detectors/driftDetector.ts src/detectors/driftDetector.test.ts
git commit -m "feat: add rule-based drift detector for header/secret/grade changes"
```

---

## Task 8: Background service worker

**Files:**
- Create: `src/background/index.ts`
- Test: `src/background/index.test.ts`

- [ ] **Step 1: Write the failing test (for the pure helper functions only — `chrome.*` APIs are not unit-tested here, only exercised manually in Task 11)**

```typescript
// src/background/index.test.ts
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

  it('ignores malformed src attributes instead of throwing', () => {
    const html = `<script src="::not a url::"></script>`;
    expect(() => extractScriptUrls(html, 'https://example.com/')).not.toThrow();
    expect(extractScriptUrls(html, 'https://example.com/')).toEqual([]);
  });
});

describe('shortLabel', () => {
  it('returns just the filename portion of a URL', () => {
    expect(shortLabel('https://cdn.example.com/assets/bundle.a1b2.js')).toBe('bundle.a1b2.js');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/background/index.test.ts`
Expected: FAIL — `Cannot find module './index'`

- [ ] **Step 3: Write `src/background/index.ts`**

```typescript
import { analyzeHeaders, computeGrade } from '../detectors/headerAnalyzer';
import { applyAttackMappings } from '../detectors/attackMapper';
import { scanSourceForSecrets } from '../detectors/secretsScanner';
import { detectDrift } from '../detectors/driftDetector';
import { HistoryStore, ChromeLocalStorage } from '../storage/historyStore';
import { Finding, ScanResult, ScanSnapshot } from '../detectors/types';

export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const regex = /<script[^>]+src=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(html)) !== null) {
    try {
      urls.push(new URL(match[1], baseUrl).toString());
    } catch {
      // ignore malformed src attributes
    }
  }
  return urls;
}

export function shortLabel(url: string): string {
  const parts = url.split('/');
  return parts[parts.length - 1] || url;
}

const historyStore = new HistoryStore(new ChromeLocalStorage());

async function runScan(url: string): Promise<ScanResult> {
  const domain = new URL(url).hostname;
  const isHttps = url.startsWith('https://');

  const response = await fetch(url, { credentials: 'include' });
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const html = await response.text();
  const scriptUrls = extractScriptUrls(html, url);

  let scannedScriptCount = 0;
  let skippedScriptCount = 0;
  let secretFindings: Finding[] = [];
  for (const scriptUrl of scriptUrls) {
    try {
      const scriptResp = await fetch(scriptUrl);
      const scriptSource = await scriptResp.text();
      secretFindings = secretFindings.concat(scanSourceForSecrets(scriptSource, shortLabel(scriptUrl)));
      scannedScriptCount++;
    } catch {
      skippedScriptCount++;
    }
  }

  const cookies = await chrome.cookies.getAll({ url });
  const cookieFlags = cookies.map((c) => ({ secure: c.secure, sameSite: c.sameSite }));
  const mixedContentUrls = scriptUrls.filter((u) => isHttps && u.startsWith('http://'));

  let headerFindings = analyzeHeaders({ headers, isHttps, mixedContentUrls, cookies: cookieFlags });
  headerFindings = applyAttackMappings(headerFindings);

  const allFindings = [...headerFindings, ...secretFindings];
  const grade = computeGrade(allFindings);

  const headerFlags: Record<string, boolean> = {
    csp: !!headers['content-security-policy'],
    hsts: !!headers['strict-transport-security'],
    frameOptions: !!headers['x-frame-options'],
    contentTypeOptions: !!headers['x-content-type-options'],
    referrerPolicy: !!headers['referrer-policy'],
    permissionsPolicy: !!headers['permissions-policy'],
  };

  const snapshot: ScanSnapshot = {
    domain,
    timestamp: Date.now(),
    headerFlags,
    cookieFlags: {
      secure: cookieFlags.every((c) => c.secure),
      sameSite: cookieFlags.every((c) => !!c.sameSite && c.sameSite !== 'no_restriction'),
    },
    secretsCount: secretFindings.length,
    grade,
  };

  const previous = await historyStore.getLatest(domain);
  const driftFindings = detectDrift(snapshot, previous);
  await historyStore.appendSnapshot(domain, snapshot);

  return {
    domain,
    timestamp: snapshot.timestamp,
    grade,
    findings: allFindings,
    driftFindings,
    scannedScriptCount,
    skippedScriptCount,
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'SCAN_REQUEST' && typeof message.url === 'string') {
    runScan(message.url)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: String(err) }));
    return true;
  }
  if (message?.type === 'GET_HISTORY' && typeof message.domain === 'string') {
    historyStore.getHistory(message.domain).then(sendResponse);
    return true;
  }
  return false;
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/background/index.test.ts`
Expected: PASS (3 tests). Note: this file also registers a `chrome.runtime.onMessage` listener at import time — under Vitest without a `chrome` global this line runs but does nothing meaningful; that's fine, it isn't exercised by these tests.

- [ ] **Step 5: Commit**

```bash
git add src/background/index.ts src/background/index.test.ts
git commit -m "feat: wire background service worker (scan pipeline + message handlers)"
```

---

## Task 9: Popup components — GradeRing and FindingCard

**Files:**
- Create: `src/popup/components/GradeRing.tsx`
- Create: `src/popup/components/FindingCard.tsx`

- [ ] **Step 1: Write `src/popup/components/GradeRing.tsx`**

```tsx
const GRADE_COLORS: Record<string, string> = {
  'A+': '#22C55E',
  A: '#22C55E',
  'B+': '#84CC16',
  B: '#F59E0B',
  'B-': '#F59E0B',
  C: '#F97316',
  D: '#EF4444',
  F: '#EF4444',
};

const GRADE_ORDER = ['F', 'D', 'C', 'B-', 'B', 'B+', 'A', 'A+'];

function gradeToPercent(grade: string): number {
  const idx = GRADE_ORDER.indexOf(grade);
  return idx === -1 ? 0 : ((idx + 1) / GRADE_ORDER.length) * 100;
}

export default function GradeRing({ grade }: { grade: string }) {
  const color = GRADE_COLORS[grade] ?? '#94A3B8';
  const percent = gradeToPercent(grade);
  const circumference = 2 * Math.PI * 16;
  const dash = (percent / 100) * circumference;

  return (
    <div className="grade-ring">
      <svg viewBox="0 0 36 36" width="46" height="46">
        <circle cx="18" cy="18" r="16" fill="none" stroke="#272F42" strokeWidth="3" />
        <circle
          cx="18"
          cy="18"
          r="16"
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          transform="rotate(-90 18 18)"
        />
      </svg>
      <span className="grade-ring-label" style={{ color }}>
        {grade}
      </span>
    </div>
  );
}
```

- [ ] **Step 2: Write `src/popup/components/FindingCard.tsx`**

```tsx
import { Finding } from '../../detectors/types';

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  high: 'High',
  medium: 'Med',
  low: 'Low',
  info: 'Info',
};

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="finding-card">
      <div>
        <div className="finding-title">{finding.title}</div>
        {finding.attackTechniqueId && (
          <div className="finding-technique">
            {finding.attackTechniqueId} · {finding.attackTechniqueName}
          </div>
        )}
      </div>
      <span className={`severity-badge severity-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add src/popup/components/GradeRing.tsx src/popup/components/FindingCard.tsx
git commit -m "feat: add GradeRing and FindingCard popup components"
```

---

## Task 10: Popup app shell, tabs, styling, and entry point

**Files:**
- Create: `src/popup/App.tsx`
- Create: `src/popup/main.tsx`
- Create: `src/popup/popup.html`
- Create: `src/popup/Popup.css`

- [ ] **Step 1: Write `src/popup/App.tsx`**

```tsx
import { useEffect, useState } from 'react';
import { ScanResult, ScanSnapshot } from '../detectors/types';
import GradeRing from './components/GradeRing';
import FindingCard from './components/FindingCard';
import './Popup.css';

type TabName = 'overview' | 'findings' | 'history';

export default function App() {
  const [tab, setTab] = useState<TabName>('overview');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanSnapshot[]>([]);

  async function scan() {
    setLoading(true);
    setError(null);
    try {
      const [tabInfo] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabInfo?.url) throw new Error('No active tab URL');
      const response = await chrome.runtime.sendMessage({ type: 'SCAN_REQUEST', url: tabInfo.url });
      if (response?.error) throw new Error(response.error);
      setResult(response as ScanResult);
      const domain = new URL(tabInfo.url).hostname;
      const hist = await chrome.runtime.sendMessage({ type: 'GET_HISTORY', domain });
      setHistory(Array.isArray(hist) ? hist : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    scan();
  }, []);

  return (
    <div className="popup">
      <header className="popup-header">
        {result ? <GradeRing grade={result.grade} /> : <div className="grade-ring-placeholder" />}
        <div className="popup-header-text">
          <div className="popup-domain">{result?.domain ?? (loading ? 'Scanning...' : 'No scan yet')}</div>
          <div className="popup-sub">
            {result?.driftFindings.length
              ? result.driftFindings[0].title
              : loading
                ? 'Scanning current page'
                : 'Click re-scan to begin'}
          </div>
        </div>
      </header>

      <nav className="popup-tabs">
        <button className={tab === 'overview' ? 'tab active' : 'tab'} onClick={() => setTab('overview')}>
          Overview
        </button>
        <button className={tab === 'findings' ? 'tab active' : 'tab'} onClick={() => setTab('findings')}>
          Findings{result ? ` (${result.findings.length})` : ''}
        </button>
        <button className={tab === 'history' ? 'tab active' : 'tab'} onClick={() => setTab('history')}>
          History
        </button>
      </nav>

      <main className="popup-content">
        {error && <div className="error-banner">{error}</div>}

        {tab === 'overview' && result && (
          <>
            {result.driftFindings.map((f) => (
              <div key={f.id} className="drift-callout">
                {f.title}
              </div>
            ))}
            <div className="section-label">Top issues</div>
            {result.findings.slice(0, 2).map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
            {result.skippedScriptCount > 0 && (
              <div className="skip-note">{result.skippedScriptCount} script(s) couldn't be scanned (blocked by CORS)</div>
            )}
          </>
        )}

        {tab === 'findings' && result && (
          <>
            {result.findings.length === 0 && <div className="empty-state">No issues found.</div>}
            {result.findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </>
        )}

        {tab === 'history' && (
          <>
            {history.length === 0 && <div className="empty-state">No scan history yet for this domain.</div>}
            {history
              .slice()
              .reverse()
              .map((h) => (
                <div key={h.timestamp} className="history-row">
                  <span>{new Date(h.timestamp).toISOString().slice(0, 10)}</span>
                  <span className="history-grade">{h.grade}</span>
                </div>
              ))}
          </>
        )}
      </main>

      <button className="rescan-button" onClick={scan} disabled={loading}>
        {loading ? 'Scanning...' : 'Re-scan this page'}
      </button>
    </div>
  );
}
```

- [ ] **Step 2: Write `src/popup/main.tsx`**

```tsx
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
```

- [ ] **Step 3: Write `src/popup/popup.html`**

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>SentinelScan</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 4: Write `src/popup/Popup.css`**

```css
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  width: 380px;
  background: #0f172a;
  color: #f8fafc;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
}

.popup-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 16px 12px;
  border-bottom: 1px solid #272f42;
}

.grade-ring {
  position: relative;
  width: 46px;
  height: 46px;
  flex-shrink: 0;
}
.grade-ring-label {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: 13px;
}
.grade-ring-placeholder {
  width: 46px;
  height: 46px;
  border-radius: 50%;
  background: #272f42;
}

.popup-header-text {
  flex: 1;
  min-width: 0;
}
.popup-domain {
  font-weight: 600;
  font-size: 13.5px;
  font-family: 'JetBrains Mono', monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.popup-sub {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 2px;
}

.popup-tabs {
  display: flex;
  padding: 0 16px;
  border-bottom: 1px solid #272f42;
}
.tab {
  background: none;
  border: none;
  color: #94a3b8;
  font-family: inherit;
  padding: 10px 0;
  margin-right: 20px;
  font-size: 12.5px;
  font-weight: 500;
  cursor: pointer;
  border-bottom: 2px solid transparent;
}
.tab.active {
  color: #f8fafc;
  font-weight: 600;
  border-bottom-color: #22c55e;
}

.popup-content {
  padding: 14px 16px;
  max-height: 340px;
  overflow-y: auto;
}

.drift-callout {
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.35);
  border-radius: 8px;
  padding: 10px 12px;
  font-size: 12px;
  color: #fbbf24;
  margin-bottom: 12px;
}

.section-label {
  font-size: 10.5px;
  font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 8px;
}

.finding-card {
  background: #1b2336;
  border: 1px solid #272f42;
  border-radius: 9px;
  padding: 11px 12px;
  margin-bottom: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}
.finding-title {
  font-size: 12.5px;
  font-weight: 500;
}
.finding-technique {
  font-size: 10.5px;
  color: #94a3b8;
  font-family: 'JetBrains Mono', monospace;
  margin-top: 3px;
}

.severity-badge {
  font-size: 10px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 6px;
  white-space: nowrap;
}
.severity-high {
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}
.severity-medium {
  background: rgba(245, 158, 11, 0.15);
  color: #fbbf24;
}
.severity-low {
  background: rgba(148, 163, 184, 0.15);
  color: #94a3b8;
}
.severity-info {
  background: rgba(148, 163, 184, 0.1);
  color: #94a3b8;
}

.history-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid #272f42;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
}
.history-grade {
  color: #f59e0b;
  font-weight: 600;
}

.empty-state,
.skip-note {
  font-size: 11.5px;
  color: #94a3b8;
  padding: 8px 0;
}
.error-banner {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: #f87171;
  border-radius: 8px;
  padding: 10px 12px;
  font-size: 12px;
  margin-bottom: 12px;
}

.rescan-button {
  display: block;
  width: calc(100% - 32px);
  margin: 0 16px 16px;
  background: #22c55e;
  color: #0f172a;
  border: none;
  border-radius: 8px;
  padding: 11px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
}
.rescan-button:disabled {
  opacity: 0.6;
  cursor: default;
}
```

- [ ] **Step 5: Run the full test suite to confirm nothing broke**

Run: `npx vitest run`
Expected: PASS — all prior suites (headerAnalyzer, secretsScanner, attackMapper, historyStore, driftDetector, background/index) still passing

- [ ] **Step 6: Commit**

```bash
git add src/popup/App.tsx src/popup/main.tsx src/popup/popup.html src/popup/Popup.css
git commit -m "feat: build popup app shell with Overview/Findings/History tabs"
```

---

## Task 11: Build verification and manual smoke test

**Files:** none created — this task verifies the build and exercises the extension for real.

- [ ] **Step 1: Run the production build**

Run: `npm run build`
Expected: `dist/` is created containing `manifest.json`, `background.js`, `popup.html`, `assets/`, and `icons/icon16.png` / `icon48.png` / `icon128.png`

- [ ] **Step 2: Load the unpacked extension in Chrome**

In Chrome: go to `chrome://extensions`, enable **Developer mode** (top right), click **Load unpacked**, select the `dist/` folder.
Expected: "SentinelScan" appears in the extensions list with the green placeholder icon, no errors shown on the card.

- [ ] **Step 3: Manually exercise a real scan**

Navigate to any HTTPS site, click the SentinelScan toolbar icon, click "Re-scan this page" if it doesn't scan automatically.
Expected: popup shows a grade, Overview tab shows top issues (or "No issues found" if the site is well-configured), Findings tab shows the full list, History tab shows one entry after the first scan.

- [ ] **Step 4: Re-scan the same site to confirm drift detection works**

Scan the same site again immediately.
Expected: since nothing changed, no drift callouts appear, and History tab now shows two entries with the same grade.

- [ ] **Step 5: Record the verification in a commit** (no code changes — this documents that manual verification happened, per this project's honesty-about-real-runs convention established in the existing cybersecurity portfolio)

```bash
git commit --allow-empty -m "test: manually verified popup scan + drift detection against a live site

Loaded dist/ as an unpacked extension, scanned a real HTTPS site twice
in a row. First scan produced a grade and findings list; second scan
against the unchanged site produced no drift findings, confirming the
diff logic doesn't false-positive on an unchanged site."
```

---

## Task 12: Docs sync — README, Obsidian, privacy policy, push

**Files:**
- Modify: `README.md`
- Modify: `/Users/marcelslowly/Documents/Obsidian Vault/01 Projects/SentinelScan/SentinelScan.md`
- Create: `/Users/marcelslowly/Documents/Obsidian Vault/01 Projects/SentinelScan/Build Log.md`
- Create: `PRIVACY.md`

- [ ] **Step 1: Write `PRIVACY.md`**

```markdown
# Privacy Policy — SentinelScan

SentinelScan runs entirely on your device.

- No data is ever transmitted to any server. There is no backend.
- No analytics, telemetry, or tracking of any kind.
- Scan results and history are stored only in your browser's local extension storage (`chrome.storage.local`), scoped to your device.
- The extension only reads data on the tab you explicitly click "scan" on (`activeTab` permission) — it does not run in the background on pages you haven't scanned.
- Cookie flag inspection uses the `cookies` permission, scoped to the page you scan, solely to check `Secure`/`SameSite` flags. Cookie values themselves are never read or stored.

You can delete all stored history at any time by removing the extension.
```

- [ ] **Step 2: Update `README.md`** — replace the "Status" line

Find: `**Status:** Design complete, implementation starting.`
Replace with: `**Status:** v1 implemented and manually verified against a live site. See [\`PRIVACY.md\`](PRIVACY.md) for the privacy policy and [the design spec](docs/superpowers/specs/2026-09-02-sentinelscan-design.md) for the full architecture.`

- [ ] **Step 3: Commit and push**

```bash
git add PRIVACY.md README.md
git commit -m "docs: add privacy policy, update README status to v1 implemented"
git push
```

- [ ] **Step 4: Update the Obsidian index note**

Update `/Users/marcelslowly/Documents/Obsidian Vault/01 Projects/SentinelScan/SentinelScan.md`: change the `status` frontmatter field from `design-complete` to `v1-implemented`, and update the "Status" section to read: "v1 implemented 2026-09-02: header/config analyzer, secrets scanner, ATT&CK mapper, drift detector, and popup UI all built and unit-tested. Manually verified against a live site. Not yet published to the Chrome Web Store — pending developer account registration."

- [ ] **Step 5: Write the Obsidian Build Log**

Create `/Users/marcelslowly/Documents/Obsidian Vault/01 Projects/SentinelScan/Build Log.md`:

```markdown
---
tags: [sentinelscan, build-log]
type: build-log
created: 2026-09-02
---

# SentinelScan — Build Log

Part of [[01 Projects/SentinelScan/SentinelScan|SentinelScan]].

## 2026-09-02 — v1 built end-to-end

Scaffolded a Vite + TypeScript + React Manifest V3 extension and implemented all four detection pieces from the [[01 Projects/SentinelScan/Design|design spec]], each TDD'd with Vitest:

- **Header/Config Analyzer** — CSP quality (not just presence), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, mixed content, cookie Secure/SameSite flags. 7 tests.
- **Secrets Scanner** — known-pattern regex (AWS, Stripe, Slack, Google, JWT, private keys) plus Shannon-entropy scoring for unmatched high-randomness strings. 4 tests.
- **ATT&CK Mapper** — static lookup table attaching MITRE technique IDs to specific finding types. 2 tests.
- **Drift Detector** — rule-based diffing against the previous scan snapshot (lost headers, new secrets, grade drops). 6 tests.
- **History Store** — `chrome.storage.local` wrapper, capped at 20 snapshots per domain, built against an injectable storage interface so it's testable without a real `chrome` global. 3 tests.
- **Background service worker** — one deviation from the spec: header capture is done via a direct background `fetch()` re-request rather than `webRequest`, since `webRequest` observation doesn't attach cleanly to a scan triggered after the page already loaded, under MV3's service-worker model. Same passive, local-only result.
- **Popup UI** — React + TypeScript, tabbed Overview/Findings/History, dark developer-tool theme from the UI/UX design-system lookup (colors, JetBrains Mono for technical strings, SVG icons only).

Placeholder icons generated with a zero-dependency Node PNG encoder (flat green squares) — functional but not final branding; swap before Chrome Web Store submission.

Manually verified: loaded `dist/` as an unpacked extension, scanned a real HTTPS site twice — first scan produced a grade and findings, second scan against the unchanged site produced zero drift findings (confirms the diff logic doesn't false-positive).

**Not done yet:** Chrome Web Store publishing (needs a $5 developer account under Marcel's own Google account — flagged for him to do directly), the opt-in watchlist fast-follow, and statistical (rather than rule-based) drift scoring once more scan history accumulates.
```

- [ ] **Step 6: Confirm the final state**

Run: `cd ~/Downloads/extension-project && git log --oneline && git status`
Expected: a clean working tree, `main` up to date with `origin/main`, and a commit history showing scaffold → each detector → background wiring → popup UI → docs, in that order.
