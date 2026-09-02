# SentinelScan

A Chrome extension that gives any website a real security report card, on demand — combining passive header/config analysis, a JS-source secrets scanner, and local historical drift detection (flagging when a site's security posture changes between visits), with findings explained in MITRE ATT&CK technique terms.

Runs entirely client-side. No server, no analytics, nothing transmitted anywhere.

**Status:** v1 implemented — all detection modules built and unit-tested (25 tests passing), production build verified. Not yet manually smoke-tested as a loaded browser extension (pending: load `dist/` as an unpacked extension in Chrome — see the Build Log), and not yet published to the Chrome Web Store (pending: developer account registration). See [`docs/superpowers/specs/2026-09-02-sentinelscan-design.md`](docs/superpowers/specs/2026-09-02-sentinelscan-design.md) for the full design spec and [`PRIVACY.md`](PRIVACY.md) for the privacy policy.

## Development

```bash
npm install
npm test    # run the unit test suite (Vitest)
npm run build   # generate icons + build the extension to dist/
```

Then load `dist/` as an unpacked extension via `chrome://extensions` → Developer mode → Load unpacked.

## Why

Existing tools each do one piece of this well (header graders, secrets scanners) but none track a site's security posture over time or explain findings in attacker-technique terms. See the spec's "Competitive landscape" section for the specific tools checked.

## Stack

TypeScript + React (popup UI), Manifest V3, `activeTab` permission only — no broad host permissions, no background auto-scanning in v1.
