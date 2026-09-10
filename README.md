# Dependency Version Risk

CVE, stale, and EOL findings for npm and Python dependencies — in the editor, not a separate dashboard.

Open a project with a lockfile. The **Dep Risk** sidebar groups packages by Critical / High / Stale / EOL. Squiggles appear on the matching lines in `package.json`, `pyproject.toml`, and `requirements.txt`. **Ask Agent to Upgrade + Fix** sends Cursor Agent a prompt with a safe target version (not a blind bump to latest).

## What it checks

- **CVEs** via [OSV.dev](https://osv.dev) (GitHub Advisory, PyPI, and other ecosystem sources)
- **Stale packages** — major versions behind, or no publish in ~18 months
- **EOL** — pinned Node or Python versions via [endoflife.date](https://endoflife.date)

Lockfiles: npm (`package-lock.json`, pnpm, Yarn, Bun) and Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements*.txt`).

## Use

1. Install the extension and open a folder with a lockfile.
2. Command Palette → **Dep Risk: Show Sidebar**, or look for **Dep Risk** in the activity bar / Explorer.
3. Click a package for advisories, or use the sparkle to ask the agent to upgrade and fix breakage.

## Develop

```bash
npm install
npm run verify
```

Then **Run Extension** (F5). The sidebar only appears in the Extension Development Host window.

## Settings

`depRisk.*` in Settings: stale major threshold, maintainer inactivity, EOL horizon, transitive scanning, daily rescan.
