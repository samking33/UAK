# URL Audit Kit

SOC-style URL security platform with persistent telemetry, local scan history, and threat intelligence views.

## Features
- Single Next.js application suitable for managed Node.js hosting
- SOC dashboard UI with scanner, threat intel, history, reports, indicators, and settings views
- Same-origin API routes for scans, reports, IOC feeds, and dashboard analytics
- Deterministic risk scoring (`LOW/MEDIUM/HIGH/CRITICAL`) with host-friendly local persistence

## Quick Start

### Local Dev
```bash
cp .env.example .env
npm install
npm run dev
```

App default: `http://localhost:3000`

The root scripts sync the committed `.env` into the Next.js app before build/start so the managed Node.js deployment path can run from the repo root.

## API Highlights
- `POST /api/audit` (`url`, optional `scan_mode=scan|deep|sandbox`)
- `GET /api/dashboard/overview`
- `GET /api/scans`, `GET /api/scans/{scan_id}`, `GET /api/scans/{scan_id}/report`
- `GET /api/iocs`
- `GET /api/threat-intelligence/map`

## Legacy Python Tooling

The original Python scanner sources are still in the repo for reference and CLI use.

```bash
source .venv/bin/activate
python cli.py https://example.com --json report.json
```

## Hostinger

Deployment instructions for Hostinger managed Node.js hosting are in [HOSTINGER.md](/Users/samking33/Downloads/UAK/HOSTINGER.md).

## Environment
See `.env.example` for optional scanner/reputation/AI keys.
