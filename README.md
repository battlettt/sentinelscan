# SentinelScan

A Chrome extension that gives any website a real security report card, on demand — combining passive header/config analysis, a JS-source secrets scanner, supply-chain (Subresource Integrity) checking, and local historical drift detection (flagging when a site's security posture changes between visits), with findings explained in MITRE ATT&CK technique terms.

Runs entirely client-side. No server, no analytics, nothing transmitted anywhere.

**Status:** v1.1 implemented — 42 unit tests passing, production build verified. Two real bugs were found and fixed during live testing (a background-fetch permissions issue, and an unhandled `chrome://` page case); a clean live scan against a real site has not yet been confirmed after those fixes. Not yet published to the Chrome Web Store (pending: developer account registration). See [`docs/superpowers/specs/2026-09-02-sentinelscan-design.md`](docs/superpowers/specs/2026-09-02-sentinelscan-design.md) for the full design spec, [`PRIVACY.md`](PRIVACY.md) for the privacy policy, and the Obsidian Build Log for the full session-by-session history.

## What's in v1.1

- **Header/config analysis** — CSP quality (not just presence), HSTS, frame protection, content-type options, referrer/permissions policy, mixed content, cookie flags — each with a ready-to-paste **Express and Nginx fix snippet**.
- **Secrets scanner** — known-pattern regex (AWS, Stripe, Slack tokens/webhooks, Google, GitHub, JWTs, private keys) plus Shannon-entropy detection for unmatched high-randomness strings.
- **Supply-chain / SRI check** — flags cross-origin scripts with no Subresource Integrity hash, the exact gap behind Magecart-style attacks (e.g. British Airways 2018).
- **Local drift detection** — flags header regressions, new secrets, new SRI gaps, and grade drops since your last scan of a domain.
- **MITRE ATT&CK mapping** — every finding links to the real attack technique it enables.
- **Personal cross-domain benchmark** — "your average across N sites scanned," computed only from your own local history, never external data.
- **Toolbar badge** — shows the grade letter on the extension icon after a scan, clears on navigation.
- **Copy report as Markdown** — one click, clipboard only, no server involved.

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

TypeScript + React (popup UI), Manifest V3. Permissions: `activeTab` (manual, on-click scanning — no broad host permissions, no background auto-scanning), `scripting` (runs the actual header/script fetch as an injected function in the page itself, since `activeTab` doesn't cover background-initiated network requests), `cookies` (Secure/SameSite flag inspection), `storage` (local scan history).
