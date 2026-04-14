# Hostinger Deploy

This repo is prepared to deploy as a single Node.js application from GitHub on Hostinger.

## Repo Root Settings

Use the repository root as the project root in Hostinger.

- Install command: `npm install`
- Build command: `npm run build`
- Start command: `npm run start`
- Node.js version: `20`

## How It Works

- Hostinger installs from the root [package.json](/Users/samking33/Downloads/UAK/package.json)
- The root `postinstall` script copies the root `.env` into `frontend/.env.local`
- The actual app build and runtime are handled by the Next.js app in [frontend/package.json](/Users/samking33/Downloads/UAK/frontend/package.json)

## Important Notes

- This deploy path assumes a single managed Node.js app, not a separate Python backend
- Runtime scan history is stored locally by the Node app, so redeploys or storage resets may clear historical data unless you attach persistent storage later
- If you prefer safer secret handling, put the same env values into Hostinger environment variables instead of relying on a committed `.env`
