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
