import { useEffect, useState } from 'react';
import { ScanResult, ScanSnapshot } from '../detectors/types';
import { gradeRank, rankToGrade } from '../detectors/gradeScale';
import GradeRing from './components/GradeRing';
import FindingCard from './components/FindingCard';
import './Popup.css';

type TabName = 'overview' | 'findings' | 'history';

const RESTRICTED_SCHEMES = ['chrome:', 'chrome-extension:', 'edge:', 'about:', 'devtools:'];
// Backstop only. Every fetch inside the scan pipeline already has its own timeout, so
// this should never actually fire — but if it ever does (an unforeseen hang somewhere),
// the popup shows a clear error instead of spinning forever with no way to tell if
// anything is still happening.
const SCAN_TIMEOUT_MS = 20000;

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(message)), ms)),
  ]);
}

function buildMarkdownReport(result: ScanResult): string {
  const lines = [
    `# SentinelScan report — ${result.domain}`,
    ``,
    `Grade: **${result.grade}** — scanned ${new Date(result.timestamp).toISOString()}`,
    ``,
  ];
  if (result.findings.length === 0) {
    lines.push('No issues found.');
  } else {
    for (const f of result.findings) {
      const technique = f.attackTechniqueId ? ` (${f.attackTechniqueId} · ${f.attackTechniqueName})` : '';
      lines.push(`- **[${f.severity.toUpperCase()}]** ${f.title}${technique}`);
    }
  }
  lines.push('', '_Generated locally by SentinelScan — no data left your device._');
  return lines.join('\n');
}

export default function App() {
  const [tab, setTab] = useState<TabName>('overview');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanSnapshot[]>([]);
  const [allStats, setAllStats] = useState<ScanSnapshot[]>([]);
  const [copied, setCopied] = useState(false);

  async function scan() {
    setLoading(true);
    setError(null);
    try {
      const [tabInfo] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabInfo?.url || typeof tabInfo.id !== 'number') throw new Error('No active tab available to scan');
      if (RESTRICTED_SCHEMES.includes(new URL(tabInfo.url).protocol)) {
        throw new Error("Can't scan browser-internal pages — open a real website and try again.");
      }
      const response = await withTimeout(
        chrome.runtime.sendMessage({ type: 'SCAN_REQUEST', tabId: tabInfo.id, url: tabInfo.url }),
        SCAN_TIMEOUT_MS,
        'Scan timed out. The site may be slow or unresponsive — try again.',
      );
      if (response?.error) throw new Error(response.error);
      setResult(response as ScanResult);
      const domain = new URL(tabInfo.url).hostname;
      const hist = await chrome.runtime.sendMessage({ type: 'GET_HISTORY', domain });
      setHistory(Array.isArray(hist) ? hist : []);
      const stats = await chrome.runtime.sendMessage({ type: 'GET_ALL_STATS' });
      setAllStats(Array.isArray(stats) ? stats : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function copyReport() {
    if (!result) return;
    await navigator.clipboard.writeText(buildMarkdownReport(result));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const averageGrade =
    allStats.length > 1 ? rankToGrade(allStats.reduce((sum, s) => sum + gradeRank(s.grade), 0) / allStats.length) : null;

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
              <div className="skip-note">
                {result.skippedScriptCount} script(s) not scanned (blocked, timed out, or over the per-scan limit)
              </div>
            )}
            <button className="copy-report-button" onClick={copyReport}>
              {copied ? 'Copied to clipboard' : 'Copy report as Markdown'}
            </button>
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
            {averageGrade && (
              <div className="benchmark-callout">
                Your average across {allStats.length} site{allStats.length === 1 ? '' : 's'} scanned:{' '}
                <strong>{averageGrade}</strong>
              </div>
            )}
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
