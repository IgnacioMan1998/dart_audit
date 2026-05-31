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
