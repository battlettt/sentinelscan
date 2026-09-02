# Privacy Policy — SentinelScan

SentinelScan runs entirely on your device.

- No data is ever transmitted to any server. There is no backend.
- No analytics, telemetry, or tracking of any kind.
- Scan results and history are stored only in your browser's local extension storage (`chrome.storage.local`), scoped to your device.
- The extension only reads data on the tab you explicitly click "scan" on (`activeTab` permission) — it does not run in the background on pages you haven't scanned.
- Cookie flag inspection uses the `cookies` permission, scoped to the page you scan, solely to check `Secure`/`SameSite` flags. Cookie values themselves are never read or stored.

You can delete all stored history at any time by removing the extension.
