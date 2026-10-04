# Architecture

Dependency Version Risk is a VS Code / Cursor extension. It reads a workspace's lockfiles, asks public data sources (OSV, npm, PyPI, endoflife.date) about each package, scores the results into risk tiers, and shows them in a sidebar, as editor squiggles on manifests, and in the status bar. It can also rewrite a manifest to a safe version.

`src/extension.ts` is bundled by esbuild (`esbuild.js`) into `dist/extension.js`; `vscode` is external.

## Module map

| Folder | Role |
|--------|------|
| `extension.ts`, `config.ts`, `types.ts` | Entry point, `depRisk.*` settings, shared types (`RiskResult`, `ScanSummary`, tiers) |
| `scan/` | `ScanPipeline`: orchestrates one scan |
| `lockfile/` | Parsers for npm, uv, Poetry, requirements; lockfile discovery (unsupported kinds are detected only to warn) |
| `graph/` | Finds which packages the code actually imports (JS and Python) |
| `osv/` | OSV.dev client (batch query + advisory hydration) and advisory link/text helpers |
| `registry/` | npm and PyPI metadata (latest version, last publish, changelog URL) |
| `eol/` | Runtime end-of-life lookup for Node and Python |
| `score/` | Pure tier rules: advisories + signals -> `RiskResult` |
| `cache/` | JSON cache in `.dep-risk/cache.json` |
| `diagnostics/` | Squiggles on dependency lines and the quick-fix provider |
| `commands/` | Apply Safe Fix, manifest text rewriting |
| `tree/` | Sidebar tree, overview webview, detail webview, badges |
| `util/` | HTTP with retry, bounded concurrency, semver / PEP 440, key helpers |

## Lifecycle

1. **Activation** (`activate`). Views and providers are registered synchronously, before any `await`, so the editor never shows "no data provider registered". Commands, diagnostics, the code action provider and workspace listeners follow. It ends with `bindWorkspace()` in the background.
2. **Bind** (`bindWorkspace`). Uses the first workspace folder: creates a `ScanPipeline`, loads the cache, watches manifests and lockfiles (800 ms debounce), starts the daily timer, and runs a first scan. With no folder it clears all UI.
3. **Triggers.** Initial bind, a watched file change (if `autoScanOnLockfileChange`), the daily timer, `Dep Risk: Refresh` (forced), and settings changes.
4. **`runScan`** is single-flight. A request during a running scan is queued (a forced request wins) and runs afterwards. A cancellation token covers folder changes and the progress UI's cancel button, and results are discarded if the folder changed.

## Scan pipeline

`ScanPipeline.scan` runs these phases and reports each through `onProgress`:

1. **Parse lockfiles.** Find lockfiles (capped at 50), warn about unsupported ones (pnpm, Yarn, Bun, Pipfile), then parse every npm lockfile and every file of one Python kind (uv > Poetry > requirements) and merge them.
2. **Direct dependencies.** Names from `package.json`, `pyproject.toml`, `requirements*.txt`, plus the runtime pins (`.nvmrc`, `.python-version`, `engines.node`, `requires-python`).
3. **Imports.** Scan up to 4,000 source files for imported packages; used packages are ranked above purely transitive ones.
4. **Select.** Drop git/file/workspace entries, mark direct/imported, honour `scanTransitive` and `maxPackagesPerScan` (direct and imported kept first).
5. **OSV batch.** `querybatch` returns advisory ids per package version (chunks of 1,000, paginated).
6. **Registry metadata.** Only for direct, imported or vulnerable packages, once per name, 6 at a time.
7. **Hydrate and score** (`scoreAll`). Full advisory records are fetched per id (8 at a time), registry signals attached, `scorePackage` assigns a tier, or returns nothing for a package with no risk.
8. **Runtime EOL.** Adds a result if the pinned Node/Python is end-of-life or about to be.
9. **Summarize.** Count per tier and sort (tier, then imported > direct > transitive, then name).

A failure in one package or source is recorded in `ScanSummary.errors` rather than aborting, so a result can be partial; the UI says so.

### Tier rules (`score/risk.ts`)

- **critical**: any critical advisory (public exploit, CVSS >= 9, CRITICAL label), or a high one in a package the code imports.
- **high**: any other advisory.
- **stale**: no advisories, but `staleMajorVersionsBehind` majors behind or no publish in `maintainerInactiveMonths`.
- **eol**: the declared runtime is past (or within `eolHorizonMonths` of) end-of-life.

`recommendedBump` is the smallest version that clears every advisory with a known fix (`pickSafeBumpForAdvisories`); it can be a downgrade when a fix only exists on an earlier branch.

### Cache

`RiskCache` persists to `.dep-risk/cache.json` with tables for per-version advisory ids, full advisories (keyed by id + modified time), registry metadata reduced to latest version, last publish and repo/homepage URLs (12 h TTL) and EOL data (24 h TTL). Writes are debounced and atomic (temp file + rename). A forced refresh bypasses it.

## From results to UI

After a scan, `runScan` fans out to: `DepRiskTreeProvider` (sidebar and Explorer views), `OverviewView` (tier bar webview), `DepRiskDecorationProvider` (badges via a `deprisk:` URI scheme), two `ManifestDiagnostics` instances (npm, Python) and the status bar. Only direct dependencies get squiggles, since transitive ones have no manifest line.

## Fix flow

1. A squiggle, tree row or command palette entry reaches a `depRisk.*` command (`pickRisk` is the fallback picker).
2. `ManifestCodeActions` offers two quick fixes per risk: Apply Safe Fix, Open Advisory/Changelog. They only call commands.
3. **Apply Safe Fix** (`commands/applySafeFix.ts`): `confirmRiskyBump` (modal for major bumps and downgrades) -> `rewriteNpmManifest` / `rewritePythonManifest` -> one `WorkspaceEdit` (undoable). Lockfiles are not touched.

## Limits and decisions

- Line-based parsers for TOML and requirements avoid a TOML dependency; unusual formatting may be missed.
- Python manifest rewriting only handles a single simple clause (`==`, `>=`, `~=`, `===`); anything else is reported, not guessed. npm only rewrites plain `1.2.3` specs with an optional `^ ~ >=` prefix.
- Import detection is textual and approximate; Python import names can differ from PyPI names.
- Caps: 50 lockfiles, 200 `package.json`, 4,000 source files, `maxPackagesPerScan` packages. Hitting one is reported in the scan errors.
- Untrusted data (advisory text, URLs) is escaped in webviews and only `http(s)` links are opened (`util/openUrl.ts`).

## Testing

`npm test` runs `test/*.test.ts` with `node:test` via `tsx` (scoring, parsers, version math, cache, rewriting, presentation). `npm run verify` = typecheck + tests + build. For manual checks press F5 and open `fixtures/sample-app`.
