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
