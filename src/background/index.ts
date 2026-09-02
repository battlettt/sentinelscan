import { analyzeHeaders, computeGrade } from '../detectors/headerAnalyzer';
import { applyAttackMappings } from '../detectors/attackMapper';
import { scanSourceForSecrets } from '../detectors/secretsScanner';
import { detectDrift } from '../detectors/driftDetector';
import { HistoryStore, ChromeLocalStorage } from '../storage/historyStore';
import { Finding, ScanResult, ScanSnapshot } from '../detectors/types';

export function shortLabel(url: string): string {
  const parts = url.split('/');
  return parts[parts.length - 1] || url;
}

interface PageData {
  headers: Record<string, string>;
  isHttps: boolean;
  scripts: { url: string; source: string | null }[];
}

// Runs inside the page itself (via chrome.scripting.executeScript), not the background
// service worker. activeTab grants this injected function the same origin access the
// page already has, which a background-initiated fetch() does NOT get for free — that
// gap is exactly what caused every scan to fail with a fetch error before this fix.
async function collectPageData(): Promise<PageData> {
  const res = await fetch(location.href, { credentials: 'include' });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const scriptUrls = Array.from(document.querySelectorAll('script[src]'))
    .map((el) => (el as HTMLScriptElement).src)
    .filter(Boolean);

  const scripts: { url: string; source: string | null }[] = [];
  for (const scriptUrl of scriptUrls) {
    try {
      const scriptRes = await fetch(scriptUrl);
      scripts.push({ url: scriptUrl, source: await scriptRes.text() });
    } catch {
      scripts.push({ url: scriptUrl, source: null });
    }
  }

  return { headers, isHttps: location.protocol === 'https:', scripts };
}

const historyStore = new HistoryStore(new ChromeLocalStorage());

export async function runScan(tabId: number, url: string): Promise<ScanResult> {
  const domain = new URL(url).hostname;

  const [injection] = await chrome.scripting.executeScript({
    target: { tabId },
    func: collectPageData,
  });
  const pageData = injection.result as PageData;

  let scannedScriptCount = 0;
  let skippedScriptCount = 0;
  let secretFindings: Finding[] = [];
  const mixedContentUrls: string[] = [];

  for (const script of pageData.scripts) {
    if (pageData.isHttps && script.url.startsWith('http://')) {
      mixedContentUrls.push(script.url);
    }
    if (script.source === null) {
      skippedScriptCount++;
      continue;
    }
    secretFindings = secretFindings.concat(scanSourceForSecrets(script.source, shortLabel(script.url)));
    scannedScriptCount++;
  }

  const cookies = await chrome.cookies.getAll({ url });
  const cookieFlags = cookies.map((c) => ({ secure: c.secure, sameSite: c.sameSite }));

  let headerFindings = analyzeHeaders({
    headers: pageData.headers,
    isHttps: pageData.isHttps,
    mixedContentUrls,
    cookies: cookieFlags,
  });
  headerFindings = applyAttackMappings(headerFindings);

  const allFindings = [...headerFindings, ...secretFindings];
  const grade = computeGrade(allFindings);

  const headerFlags: Record<string, boolean> = {
    csp: !!pageData.headers['content-security-policy'],
    hsts: !!pageData.headers['strict-transport-security'],
    frameOptions: !!pageData.headers['x-frame-options'],
    contentTypeOptions: !!pageData.headers['x-content-type-options'],
    referrerPolicy: !!pageData.headers['referrer-policy'],
    permissionsPolicy: !!pageData.headers['permissions-policy'],
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
    if (message?.type === 'SCAN_REQUEST' && typeof message.tabId === 'number' && typeof message.url === 'string') {
      runScan(message.tabId, message.url)
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
