import { analyzeHeaders, computeGrade } from '../detectors/headerAnalyzer';
import { applyAttackMappings } from '../detectors/attackMapper';
import { scanSourceForSecrets } from '../detectors/secretsScanner';
import { analyzeSupplyChain, ScriptRef } from '../detectors/supplyChainAnalyzer';
import { detectDrift } from '../detectors/driftDetector';
import { gradeColor } from '../detectors/gradeScale';
import { HistoryStore, ChromeLocalStorage } from '../storage/historyStore';
import { Finding, ScanResult, ScanSnapshot } from '../detectors/types';

export function shortLabel(url: string): string {
  const parts = url.split('/');
  return parts[parts.length - 1] || url;
}

interface PageScript {
  url: string;
  source: string | null;
  isCrossOrigin: boolean;
  hasIntegrity: boolean;
}

interface PageData {
  headers: Record<string, string>;
  isHttps: boolean;
  scripts: PageScript[];
  totalScriptCount: number;
}

// How many cross-page scripts to actually fetch and scan per scan. Real sites can have
// 50-100+ <script> tags (ads, trackers, chunked bundles); without a cap, a scan can run
// long enough to risk the MV3 service worker being torn down mid-scan (it's killed after
// ~30s of inactivity, and a slow sequential fetch chain easily exceeds that).
const MAX_SCRIPTS_PER_SCAN = 25;
// Per-resource timeout, so one slow/hanging third-party script (a stalled ad or tracker
// request) can't block the whole scan indefinitely.
const FETCH_TIMEOUT_MS = 6000;

// Runs inside the page itself (via chrome.scripting.executeScript), not the background
// service worker. activeTab grants this injected function the same origin access the
// page already has, which a background-initiated fetch() does NOT get for free — that
// gap is exactly what caused every scan to fail with a fetch error before this fix.
async function collectPageData(maxScripts: number, timeoutMs: number): Promise<PageData> {
  async function fetchWithTimeout(input: string, init?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(input, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  const res = await fetchWithTimeout(location.href, { credentials: 'include' });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const allScriptElements = (Array.from(document.querySelectorAll('script[src]')) as HTMLScriptElement[]).filter(
    (el) => !!el.src,
  );
  const scriptElements = allScriptElements.slice(0, maxScripts);

  // Fetched in parallel, not sequentially — a page with 25 scripts was taking 25x as
  // long as it needed to when each fetch waited for the previous one to finish.
  const scripts: PageScript[] = await Promise.all(
    scriptElements.map(async (el) => {
      let isCrossOrigin = false;
      try {
        isCrossOrigin = new URL(el.src).origin !== location.origin;
      } catch {
        return { url: el.src, source: null, isCrossOrigin: false, hasIntegrity: !!el.integrity };
      }

      let source: string | null = null;
      try {
        const scriptRes = await fetchWithTimeout(el.src);
        source = await scriptRes.text();
      } catch {
        source = null;
      }

      return { url: el.src, source, isCrossOrigin, hasIntegrity: !!el.integrity };
    }),
  );

  return { headers, isHttps: location.protocol === 'https:', scripts, totalScriptCount: allScriptElements.length };
}

const historyStore = new HistoryStore(new ChromeLocalStorage());

export async function runScan(tabId: number, url: string): Promise<ScanResult> {
  const domain = new URL(url).hostname;

  const [injection] = await chrome.scripting.executeScript({
    target: { tabId },
    func: collectPageData,
    args: [MAX_SCRIPTS_PER_SCAN, FETCH_TIMEOUT_MS],
  });
  const pageData = injection.result as PageData;

  let scannedScriptCount = 0;
  // Scripts beyond MAX_SCRIPTS_PER_SCAN were never attempted at all — those count as
  // skipped too, same as a CORS failure or a timeout, since they weren't scanned.
  let skippedScriptCount = pageData.totalScriptCount - pageData.scripts.length;
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

  const scriptRefs: ScriptRef[] = pageData.scripts.map((s) => ({
    url: s.url,
    isCrossOrigin: s.isCrossOrigin,
    hasIntegrity: s.hasIntegrity,
  }));
  let supplyChainFindings = analyzeSupplyChain(scriptRefs);
  supplyChainFindings = applyAttackMappings(supplyChainFindings);
  const sriMissingCount = scriptRefs.filter((s) => s.isCrossOrigin && !s.hasIntegrity).length;

  const allFindings = [...headerFindings, ...secretFindings, ...supplyChainFindings];
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
    sriMissingCount,
    grade,
  };

  const previous = await historyStore.getLatest(domain);
  const driftFindings = detectDrift(snapshot, previous);
  await historyStore.appendSnapshot(domain, snapshot);

  if (typeof chrome !== 'undefined' && chrome.action) {
    chrome.action.setBadgeText({ tabId, text: grade });
    chrome.action.setBadgeBackgroundColor({ tabId, color: gradeColor(grade) });
  }

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
    if (message?.type === 'GET_ALL_STATS') {
      historyStore.getAllLatestSnapshots().then(sendResponse);
      return true;
    }
    return false;
  });
}

// Clear the badge on navigation so it doesn't show a stale grade for the new page
// until the user re-scans it.
if (typeof chrome !== 'undefined' && chrome.tabs?.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
      chrome.action.setBadgeText({ tabId, text: '' });
    }
  });
}
