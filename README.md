# SentinelScan

A Chrome extension that gives any website a real security report card, on demand — combining passive header/config analysis, a JS-source secrets scanner, and local historical drift detection (flagging when a site's security posture changes between visits), with findings explained in MITRE ATT&CK technique terms.

Runs entirely client-side. No server, no analytics, nothing transmitted anywhere.

**Status:** Design complete, implementation starting. See [`docs/superpowers/specs/2026-09-02-sentinelscan-design.md`](docs/superpowers/specs/2026-09-02-sentinelscan-design.md) for the full design spec, including a review of existing competitor extensions and why this combination doesn't currently exist elsewhere.

## Why

Existing tools each do one piece of this well (header graders, secrets scanners) but none track a site's security posture over time or explain findings in attacker-technique terms. See the spec's "Competitive landscape" section for the specific tools checked.

## Stack

TypeScript + React (popup UI), Manifest V3, `activeTab` permission only — no broad host permissions, no background auto-scanning in v1.
