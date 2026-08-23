## 0.3.0

### Added

- **Unicode / Trojan Source scanner** (`lib/src/inspector/unicode_scanner.dart`) — detects:
  - Bi-directional override characters (CVE-2021-42574) — RTL/LTR overrides, embedding, and pop directional isolates (CRITICAL).
  - Zero-width characters (U+200B–U+200F, U+2028–U+2029, U+2060–U+2064, U+FEFF) — potential invisible injection (HIGH).
  - GlassWorm PUA carriers (U+FE00–U+FE0F variation selectors) — used to smuggle executable content (CRITICAL).
  - Cyrillic / Greek homoglyphs in identifiers — visual spoofing of variable and function names (HIGH).
  - Runs in parallel with regex and entropy scanners during `inspect`.

- **Archive structural scanner** (`lib/src/inspector/archive_scanner.dart`) — analyses `.tar.gz` archive entries before extraction:
  - Path-traversal detection (`../`, absolute paths, parent-segment traversal) — CRITICAL.
  - Suspiciously high Dart-to-total file ratio — MEDIUM.
  - Hidden executable files (`.exe`, `.dll`, `.so`, `.dylib`) — HIGH.
  - Mixed-case filenames suggesting case-confusion on case-insensitive systems — MEDIUM.
  - Entry count statistics exposed to the report.

- **Package trust scorer** (`lib/src/inspector/trust_scorer.dart`) — queries `pub.dev` API for a published package's trust signals:
  - Package age (days since first publish) — new packages (< 30 days) flagged as MEDIUM risk.
  - Fresh release detection (version published < 7 days ago) — MEDIUM.
  - Likes and download-percentile heuristics.
  - Publisher verification status.
  - Overall quality score from pub.dev.
  - Asynchronous; used by both `inspect` and the new `trust` command.

- **Typosquatting detector** (`lib/src/inspector/typosquat_detector.dart`) — compares local dependency names against ~80 known-popular pub.dev packages:
  - Levenshtein distance 1 (CRITICAL) and 2 (HIGH) matches.
  - `flutter_`, `_flutter`, `dart_`, `pub_` prefix/suffix confusion attacks (HIGH).
  - Suspicious suffix on popular-package names (MEDIUM).
  - Popular-package names are automatically skipped.

- **Dependency confusion detector** (`lib/src/inspector/confusion_detector.dart`) — flags potential internal-package namespace confusion by detecting version inflation (a local version newer than the latest pub.dev release).

- **Pubspec.yaml scanner** (`lib/src/inspector/pubspec_scanner.dart`) — analyses `pubspec.yaml` for:
  - Wildcard / `any` version constraints.
  - Suspicious Git hosts (non-GitHub, non-GitLab, non-Codeberg).
  - IP addresses and raw URLs in dependency sources.
  - Branch or tag refs (not pinned to a SHA).
  - Path dependencies.
  - Dependency overrides.
  - Very old SDK constraints (`>=2` without upper bound).

- **`trust` sub-command** — `dart_audit trust <package>` queries the pub.dev API and prints a trust assessment: age, release freshness, publisher verification, likes, downloads, and quality score.

- **`typosquat` sub-command** — `dart_audit typosquat` reads the project's `pubspec.lock` and runs both the typosquatting detector and the dependency confusion detector against all listed dependencies.

- **Updated `inspect` output** — the `inspect` command now prints Unicode findings, archive findings, and a trust assessment section alongside the existing regex and entropy results.

### Changed

- `inspect` now runs 4 scanner layers in parallel: regex, entropy, Unicode, and archive analysis.
- `PackageInspector` exposes `unicodeFindings`, `archiveReport`, and `trustAssessment` on `InspectionReport`.
- `TyposquatDetector` now skips local packages that are themselves known-popular packages.

---

## 0.2.0

### Added

- **`inspect` subcommand** — statically analyses a pub.dev package's Dart source before it enters the project, enabling supply-chain attack detection.
  - Downloads the package `.tar.gz` archive from `pub.dev` using the `archive` package; extracts only `.dart` files to a temporary directory (always cleaned up).
  - **Regex scanner** — 14 rules across 7 categories: hard-coded URLs to unknown hosts, raw TCP sockets, `Process.run` / shell injection, sensitive file-system paths, obfuscation techniques (hex encoding, Base64 eval, Unicode escapes, char-code concatenation), crypto-mining, backdoor / reverse-shell patterns, and data exfiltration markers.
  - **Shannon entropy scanner** — flags string literals with high entropy (> 4.5 bits → MEDIUM, > 5.5 bits → HIGH) as possible obfuscated payloads or embedded secrets. Minimum string length of 20 characters to reduce noise.
  - Weighted risk score 0–100 (CRITICAL regex: 40 pts, HIGH: 20 pts, MEDIUM: 10 pts; entropy HIGH: 15 pts, MEDIUM: 5 pts), clamped and labelled CLEAN / LOW RISK / SUSPICIOUS / HIGH RISK.
  - Both scanners run in parallel via `Future.wait`.
  - Exit code `1` when risk score ≥ 30 (SUSPICIOUS or worse); `--exit-zero` disables this.
  - `--format json` produces machine-readable output.
  - Throws typed `PackageNotFoundException` on 404 from pub.dev.

- **Subcommand architecture** — the CLI is now structured as `dart_audit <command> [options]` with two commands: `audit` (default) and `inspect`. A bare `dart_audit` still behaves as `audit` for backwards compatibility.

- **`--format json`** for the `audit` command — all findings and package metadata are serialised to structured JSON.

- **`--min-severity`** filter for `audit` — only reports findings at or above the specified level (low / medium / high / critical).

- **`--ignore`** flag for `audit` — suppresses specific CVE / GHSA IDs. Can be repeated.

- **`--no-color`** global flag — disables ANSI colour output. Color state is now shared via a single `color_output` module so both commands honour the flag consistently.

- **HTTP timeout and retries for `audit`** — requests to OSV.dev now time out after 30 s and are retried up to 3 times with exponential back-off (1 s, 2 s, 4 s).

- **Skipped-package warnings** — git, path, and SDK dependencies are now tracked and reported as warnings instead of being silently ignored.

- **CVSS parsing improvements** — falls back through three levels: (1) top-level `severity` array with `CVSS_V3` / `CVSS_V2` type, (2) `database_specific.severity`, (3) `affected[].database_specific.severity`.

- **Progress indicator** for large dependency trees — reports batch progress while querying OSV.dev.

- **Version read from `pubspec.yaml` at runtime** — no more hardcoded version constant.

### Fixed

- `_resolveFixedVersion` previously returned `null` even when a fix was found (dead code path). Now correctly resolves and returns the fixed version string.

---

## 0.1.0

Initial release.

### Added

- `dart_audit` CLI tool — scans `pubspec.lock` against the [OSV.dev](https://osv.dev) vulnerability database.
- `--lockfile / -l` option to specify a custom path to `pubspec.lock` (defaults to `pubspec.lock` in the current directory).
- `--verbose / -v` flag to list all packages including clean ones.
- `--exit-zero` flag for CI reporting-only mode (always exits 0 even when vulnerabilities are found).
- `--version` flag to print the current version.
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN — derived from CVSS scores and OSV database-specific fields.
- Colored terminal output using ANSI codes (auto-disabled when stdout is not a terminal).
- CVE / GHSA alias display, vulnerability summary, and available fix version for each finding.
- Batched OSV.dev API requests (up to 100 packages per request) to handle large dependency trees efficiently.
- Filters to `hosted` packages only — skips `git` and `path` dependencies not indexed by OSV.dev.
- Exit code `1` when vulnerabilities are found, enabling automatic CI/CD pipeline failure.
