# Dependency Version Risk

Live dependency risk in the editor: known CVEs (via [OSV.dev](https://osv.dev)), major-version staleness, maintainer inactivity, and runtime EOL — in a sidebar tree and as `package.json` / `pyproject.toml` / `requirements.txt` diagnostics, with an **Ask Agent to Upgrade + Fix** action.

## Beyond MVP

- **OSV `querybatch`** on lockfile inventory (chunked at 1000), then hydrate `/v1/vulns/{id}` with local cache
- **Cache** in `.dep-risk/cache.json` keyed by `name@version` and vuln id + modified timestamp, with 24-hour inventory expiry and atomic writes
- **Rescan** on lockfile change, manual refresh, and daily timer
- **Tiers**: Critical / High / Stale / EOL-adjacent
- **Used vs transitive**: import/require scan elevates high-severity issues on imported packages to Critical
- **Safe bump**: computes the minimum target that clears every advisory with a published fix; never substitutes blind `latest` for an unfixed advisory
- **Major bump gate**: modal + changelog link before firing the agent prompt
- **Lockfiles**: npm (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` classic/Berry, `bun.lock`) and Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements*.txt`). Both families are scanned when both exist; unpinned requirements are reported but not treated as CVE inventory
- **EOL**: [endoflife.date v1](https://endoflife.date/docs/api/v1/) for an explicitly pinned Node (`.nvmrc`, `.node-version`, or unambiguous `engines.node`) or Python (`.python-version`, `runtime.txt`, or an exact `requires-python`) version
- **Resilience**: transient API retries, bounded concurrency, OSV response validation, incomplete-scan warnings, and queued lockfile rescans

## Develop

```bash
npm install
npm run verify
```

Then **Run Extension** from the Debug view (F5). That opens a second **Extension Development Host** window — the sidebar, status bar, and commands only exist there.

In that window: Command Palette → **Dep Risk: Show Sidebar**, or look for **Dep Risk** at the bottom of Explorer. The **Overview** pane shows a color bar and the top critical/high packages; **Live Risks** is the expandable tree (colored badges, CVSS/usage on each row). Click a package for a detail tab that lists each OSV/GHSA issue with a **Read full advisory** link; expand the row and click an advisory id to open it. On a squiggle in `package.json`, `pyproject.toml`, or `requirements.txt`, use the lightbulb for **Ask Agent to Upgrade + Fix** or **Open Advisory**.

## Commands

| Command | Action |
|--------|--------|
| `Dep Risk: Refresh` | Force re-query OSV + refresh sidebar |
| `Dep Risk: View Risk Details` | Lists advisories for a package (click through to GHSA/OSV) |
| `Ask Agent to Upgrade + Fix` | Pre-loaded upgrade prompt (safe target + tests) |
| `Open Advisory` / `Open Changelog` | External links |

## Settings

See `depRisk.*` in Settings: stale major threshold, maintainer inactivity months, EOL horizon, transitive scanning, daily rescan hours.
