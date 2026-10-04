# Dependency Version Risk

Live dependency risk in the editor for npm and PyPI: known CVEs (via [OSV.dev](https://osv.dev)), major-version staleness, maintainer inactivity, and runtime end-of-life. Results show up in a sidebar, on the status bar, and as diagnostics in `package.json`, `pyproject.toml`, and `requirements.txt`, with an **Ask Agent to Upgrade + Fix** action.

## What it flags

| Tier | Meaning |
|------|---------|
| **Critical** | Public exploit, CVSS ≥ 9, or a `CRITICAL` advisory. A high-severity advisory on a package imported in the workspace is also Critical. |
| **High** | Any other known advisory on the installed version. |
| **Stale** | Several major versions behind latest, or no registry publish within the inactivity window. |
| **EOL-adjacent** | Pinned Node or Python runtime already past end-of-life, or within the configured horizon. |

A package with no advisory, staleness, or EOL signal is omitted from the risk lists.

## How a scan works

The extension inventories lockfiles, queries OSV, then scores each package.

- **Lockfiles.** npm: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and Berry), `bun.lock`. Python: `uv.lock`, `poetry.lock`, `Pipfile.lock`, and pinned `requirements*.txt`. Both ecosystems are scanned when both are present. Unpinned requirements are reported, but they are not sent to OSV as versioned inventory. Nested lockfiles are included, not only files at the workspace root.
- **Advisories.** OSV `querybatch` (chunked at 1,000 packages), then `/v1/vulns/{id}` for full records. Responses are validated, and transient failures are retried with bounded concurrency.
- **Usage.** An import/require scan marks packages that workspace source actually uses. That usage can raise a high-severity issue to Critical.
- **Safe bump.** The suggested upgrade is the minimum published version that clears every advisory with a fix. An advisory with no published fix never becomes a blind jump to `latest`. A major bump opens a confirmation modal with a changelog link before the agent prompt is sent.
- **EOL.** [endoflife.date](https://endoflife.date/docs/api/v1/) for an explicitly pinned Node version (`.nvmrc`, `.node-version`, or an unambiguous `engines.node`) or Python version (`.python-version`, `runtime.txt`, or an exact `requires-python`). Range declarations such as `>=18` are ignored.
- **Cache and refresh.** Results live in `.dep-risk/cache.json`, keyed by `name@version` and by advisory id plus modified timestamp. Inventory expires after 24 hours and writes are atomic. A rescan runs when a lockfile or manifest changes, when you run **Dep Risk: Refresh**, on a daily timer, and when a `depRisk` setting changes. If a scan is already running, the next one is queued. Incomplete scans surface a warning instead of a silent clear.

## Using it

**Run Extension** from the Debug view (F5) opens an Extension Development Host. The sidebar, status bar, and commands exist in that window.

In that window: Command Palette → **Dep Risk: Show Sidebar**, or open the **Dep Risk** activity-bar icon. **Dep Risk** also appears at the bottom of Explorer.

- **Overview** is a color bar plus the top critical and high packages.
- **Live Risks** is the expandable tree: colored badges, with CVSS and usage on each row. Click a package to open a detail tab that lists each OSV/GHSA issue and a **Read full advisory** link. Expand a row and click an advisory id to open it.
- The status bar shows counts by tier (`critical`, `high`, `stale`, `eol`) and turns into a warning when the last scan was incomplete.
- On a squiggle in `package.json`, `pyproject.toml`, or `requirements.txt`, the lightbulb offers **Ask Agent to Upgrade + Fix** and **Open Advisory**.

**Ask Agent to Upgrade + Fix** copies a prompt (safe target version, lockfile, and tests) and pastes it into a new agent chat. If no chat command is available, the prompt stays on the clipboard. Runtime EOL items open the endoflife.date page instead of proposing a package bump.

## Commands

| Command | Action |
|--------|--------|
| `Dep Risk: Show Sidebar` | Focus the Dep Risk view; scans if nothing is loaded yet |
| `Dep Risk: Refresh` | Force a re-query of OSV and refresh the sidebar |
| `Dep Risk: View Risk Details` | Open the advisory list for a package |
| `Apply Safe Fix` | Rewrite the dependency's version in the manifest to the safe target (run your install afterwards to refresh the lockfile) |
| `Ask Agent to Upgrade + Fix` | Pre-loaded upgrade prompt (safe target + tests) |
| `Dep Risk: Copy Agent Prompt` | Copy that prompt without opening chat |
| `Dep Risk: Open Advisory` | Open the OSV/GHSA page |
| `Dep Risk: Open Changelog / Release Notes` | Open the package changelog or release notes |

Tree rows also expose the package actions inline and from the context menu.

## Settings

Search for `depRisk` in Settings.

| Setting | Default | Effect |
|---------|---------|--------|
| `depRisk.autoScanOnLockfileChange` | `true` | Rescan when a lockfile or manifest changes |
| `depRisk.dailyRescanHours` | `24` | Background rescan interval, in hours |
| `depRisk.staleMajorVersionsBehind` | `2` | Major versions behind latest before a package is Stale |
| `depRisk.maintainerInactiveMonths` | `18` | Months since the last npm or PyPI publish before a package is Stale |
| `depRisk.eolHorizonMonths` | `6` | Months until runtime EOL to flag as EOL-adjacent |
| `depRisk.scanTransitive` | `true` | Include transitive lockfile packages in OSV queries |
| `depRisk.maxPackagesPerScan` | `1000` | Cap on packages sent to OSV per scan (1–5000; requests are chunked at 1000) |

## Develop

```bash
npm install
npm run verify
```

`verify` typechecks, runs the tests, and compiles the extension. Then press F5 and use the fixture under `fixtures/sample-app`, or open any folder that has a lockfile.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the code is organized.
