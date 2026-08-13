# Dependency Version Risk

Live dependency risk in the editor: known CVEs (via [OSV.dev](https://osv.dev)), major-version staleness, maintainer inactivity, and runtime EOL — in a sidebar tree and as `package.json` diagnostics, with an **Ask Agent to Upgrade + Fix** action.

## Beyond MVP

- **OSV `querybatch`** on lockfile inventory (chunked at 1000), then hydrate `/v1/vulns/{id}` with local cache
- **Cache** in `.dep-risk/cache.json` keyed by `name@version` and vuln id + modified timestamp, with 24-hour inventory expiry and atomic writes
- **Rescan** on lockfile change, manual refresh, and daily timer
- **Tiers**: Critical / High / Stale / EOL-adjacent
- **Used vs transitive**: import/require scan elevates high-severity issues on imported packages to Critical
- **Safe bump**: computes the minimum target that clears every advisory with a published fix; never substitutes blind `latest` for an unfixed advisory
- **Major bump gate**: modal + changelog link before firing the agent prompt
- **Lockfiles**: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic)
- **EOL**: [endoflife.date v1](https://endoflife.date/docs/api/v1/) for an explicitly pinned Node version (`.nvmrc`, `.node-version`, or an unambiguous `engines.node`)
- **Resilience**: transient API retries, bounded concurrency, OSV response validation, incomplete-scan warnings, and queued lockfile rescans

## Develop

```bash
npm install
npm run verify
```

Then **Run Extension** from the Debug view (F5).

## Commands

| Command | Action |
|--------|--------|
| `Dep Risk: Refresh` | Force re-query OSV + refresh sidebar |
| `Ask Agent to Upgrade + Fix` | Pre-loaded upgrade prompt (safe target + tests) |
| `Open Advisory` / `Open Changelog` | External links |

## Settings

See `depRisk.*` in Settings: stale major threshold, maintainer inactivity months, EOL horizon, transitive scanning, daily rescan hours.
