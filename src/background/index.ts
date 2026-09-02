import { analyzeHeaders } from '../detectors/headerAnalyzer';
import { computeGrade } from '../detectors/headerAnalyzer';
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

export async function runScan(url: string): Promise<ScanResult> {
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

// Guarded so this module can be imported under Vitest (no `chrome` global) to unit-test
// the pure helpers above without needing a real extension runtime.
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
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
}
