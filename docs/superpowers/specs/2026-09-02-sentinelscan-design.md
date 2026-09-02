# SentinelScan — Design Spec

**Date:** 2026-09-02
**Status:** Approved, ready for implementation planning
**Repo:** (to be created)

## Purpose

A Manifest V3 Chrome extension that gives any website a real security report card — on demand, entirely client-side, with no server and no data leaving the browser. It differentiates itself from existing tools (which all do exactly one of these things) by combining three things nobody currently combines:

1. Passive header/config/cookie analysis
2. A JS-source secrets scanner
3. Local historical drift detection — flagging when a site's security posture changes between visits, with findings explained in MITRE ATT&CK technique terms rather than a bare grade

### Competitive landscape (checked 2026-09-02)

- **Header/config graders already exist:** Security Headers, Security Headers Inspector, Security Header Checker, Security-Header-Extension, SiteSecurityScore — all give an instant letter grade from HTTP headers.
- **Secrets scanners already exist:** Secret Scanner, KeyFinder (80+ patterns), JS Recon & Secret Scanner, KeySec Hunter, Hide Secrets, FlashFuzz.
- **Nobody found tracks a site's *security configuration* over time.** Extension-behavior monitors (Extension Auditor Pro, The Extension Auditor) watch installed extensions, not sites you visit. Generic change-watchers (Visualping, Distill, ChangeTower) watch page content/text, not security config.
- **Nobody found maps live findings to MITRE ATT&CK.** MITRE's own extension (ATT&CK Powered Suit) is a knowledge-base search tool, not a live page analyzer.

The individual techniques are common; the combination — and specifically the drift layer plus ATT&CK framing — is not.

## Non-goals / hard boundary

**Passive analysis only.** The extension reads what a site already publicly serves to any visitor (headers, cookies, JS source, source maps). It never sends injection payloads or actively probes a site's behavior. Active testing against a site without authorization is out of scope, full stop — this is a legal and ethical line, not a feature-scoping preference.

Also out of scope for v1: full TLS/cipher-suite analysis (no reliable local-only browser API without an external service call, which would break the "nothing leaves your device" guarantee).

## Architecture

```
Popup (React + TypeScript)
   │  user clicks "Scan this page" / toolbar icon
   ▼
Background service worker
   ├─ reads response headers for the active tab (webRequest, read-only)
   ├─ fetches linked JS files within activeTab-granted permission
   └─ reads/writes chrome.storage.local (per-domain scan history)
   ▼
Detection pipeline (all local, no server)
   1. Header/Config Analyzer
   2. Secrets Scanner
   3. Drift Detector (diffs against stored history)
   ▼
ATT&CK Mapper (static local lookup table: finding → technique ID + rationale)
   ▼
Results rendered in Popup; new snapshot saved to storage
```

## Permission model

**`activeTab` only** — manual, on-click scanning. No `<all_urls>`, no background auto-scanning.

Trade-off accepted deliberately: this means drift history only accumulates for domains the user actively re-scans, rather than every site visited. In exchange: a much friendlier Chrome install prompt, faster Web Store review, and a stronger privacy story for a brand-new extension with zero reviews to build trust on. A per-site opt-in "watchlist" (using Chrome's optional per-site host permissions) is a natural fast-follow once the extension has traction, without ever requiring blanket `<all_urls>` access.

## Components

### 1. Header/Config Analyzer
Checks on each scan:
- CSP presence *and quality* — flags `unsafe-inline`/`unsafe-eval` as weak rather than treating any CSP as a pass (the depth competitors skip)
- HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Cookie `Secure` / `SameSite` flags (readable subset only — HttpOnly cookies are not visible to JS, and this limitation is stated explicitly in the UI/docs, not hidden)
- Mixed-content detection (HTTP resources loaded on an HTTPS page)

### 2. Secrets Scanner
Fetches linked JS files within `activeTab` permission scope and scans two ways:
- Known-pattern regex matching (AWS keys, Stripe keys, JWTs, Slack tokens, Google API keys — patterns in the same public style documented by Gitleaks/TruffleHog)
- Shannon-entropy scoring for high-entropy strings that don't match a known pattern — a direct reuse of the statistical framework from the existing network anomaly detector portfolio project, applied to a different detection problem

### 3. Drift Detector
Every scan produces a normalized posture snapshot (header states, cookie flags, secrets count) for the current domain, saved to `chrome.storage.local` keyed by domain with timestamped history. Each new scan diffs against the most recent prior snapshot for that domain and surfaces plain-language deltas (e.g., "CSP header was present on 2026-08-20, missing today").

v1 is honest rule-based diffing, not a statistical anomaly score — with only a handful of scans per domain early on, claiming statistical confidence would overclaim in exactly the way the rest of the security portfolio deliberately avoids. A real statistical drift score (reusing the z-score/hypothesis-testing approach from the anomaly detector project) is a fast-follow once enough scan history exists per domain to make the claim honestly.

### 4. ATT&CK Mapper
A static local JSON lookup table: finding type → MITRE technique ID + one-line plain-English rationale (e.g., missing CSP → T1189, Drive-by Compromise). No API calls, no external dependency.

### 5. Popup UI (React + TypeScript)
Tabbed layout: **Overview / Findings / History**. Overview shows the grade as a progress-ring badge, the single biggest drift factor as a callout, and top 2 issues. Findings tab lists all issues with severity tags and ATT&CK technique IDs. History tab shows the domain's scan timeline.

**Visual design** (from UI/UX design-system lookup, dark developer-tool aesthetic):
- Background `#0F172A`, card `#1B2336`, border `#475569`, foreground `#F8FAFC`
- Accent/action green `#22C55E`, drift/warning amber `#F59E0B`, high-severity red `#EF4444`
- Typography: IBM Plex Sans (UI text), JetBrains Mono (domains, header names, technique IDs)
- Icons: SVG only (Phosphor-style outline icons: Shield, Warning, WarningCircle) — no emoji, per accessibility guidance
- Mockup approved 2026-09-02 (Option B: tabbed layout, polished pass)

## Data flow & error handling

1. User clicks toolbar icon → popup messages the background service worker
2. Service worker reads captured response headers for the tab, fetches linked JS files
3. Results run through the three detection modules → ATT&CK Mapper
4. Background reads/writes domain history in `chrome.storage.local` for the drift diff
5. Results message back to the popup for render

If a JS file can't be fetched (CORS-blocked or site blocks cross-origin fetch), that resource is skipped and the UI shows "some scripts couldn't be scanned" rather than failing the whole scan.

## Testing

- Jest unit tests for header-check logic and the ATT&CK mapping table
- Secrets-detection regex/entropy scorer tested against a fixture set of known-good and known-secret sample strings
- A handful of React Testing Library smoke tests for the popup — not full coverage, not worth over-investing for v1

Matches the testing pattern already established in the existing cybersecurity portfolio (projects 5 and 9 both have unit tests).

## Privacy, permissions & store listing

`activeTab` only, no other host permissions, no analytics, no external network calls. Privacy policy for the Chrome Web Store (and the core trust/marketing pitch): *"Runs entirely locally. Nothing is transmitted anywhere. No analytics, no servers."* This claim must stay true — it is both the ethical boundary and the differentiator against tools that phone home.

## Distribution plan

Chrome Web Store listing, then a deliberate launch push: r/netsec, r/privacy, Product Hunt, and Waterloo CS/security Discord communities. Goal: genuine active users (real installs, real usage), not raw GitHub stars — the target for resume purposes is real people using it, not an unused repo.

## Timeline

4-6 week build budget. Tech stack: TypeScript + React for the popup/options UI (matches existing resume skills, and type safety matters for the parsing/detection logic where silent bugs are easy to introduce in loose JS).

## Open items for fast-follow (explicitly not v1)

- Opt-in per-site "watchlist" with automatic scanning (optional host permissions per domain)
- Statistical drift scoring (z-score/hypothesis-testing approach) once enough scan history accumulates
- TLS/cipher-suite analysis, if a privacy-preserving local method becomes available
