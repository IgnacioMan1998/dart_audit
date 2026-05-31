# dart_audit

[![pub version](https://img.shields.io/pub/v/dart_audit)](https://pub.dev/packages/dart_audit)
[![OSV.dev](https://img.shields.io/badge/powered%20by-OSV.dev-blue)](https://osv.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Security vulnerability scanner for Dart and Flutter projects.  
Checks every dependency in your `pubspec.lock` against the [OSV.dev](https://osv.dev) open vulnerability database — the same database used by GitHub Dependabot and `npm audit`.

---

## Features

- Scans **all** packages (direct and transitive) from `pubspec.lock`
- Single batched request to `api.osv.dev` — fast, no API key needed
- Colored terminal output with severity (CRITICAL / HIGH / MEDIUM / LOW)
- Shows CVE/GHSA aliases, summary, and available fix version
- Exit code `1` on findings — integrates directly into CI/CD pipelines
- `--exit-zero` flag for reporting-only mode
- `--verbose` to list all packages, including clean ones

---

## Installation

### As a global tool

```bash
dart pub global activate dart_audit
```

Make sure `~/.pub-cache/bin` is in your `PATH`. Add this to your shell profile if needed:

```bash
export PATH="$PATH:$HOME/.pub-cache/bin"
```

### As a dev dependency (project-local)

```yaml
# pubspec.yaml
dev_dependencies:
  dart_audit: ^0.1.0
```

Then run with:

```bash
dart run dart_audit
```

---

## Usage

```
Usage: dart_audit [options]

-l, --lockfile    Path to pubspec.lock. (defaults to "pubspec.lock")
-v, --verbose     Show all packages, including clean ones.
    --exit-zero   Always exit 0, even when vulnerabilities are found.
    --version     Print version and exit.
-h, --help        Show this help.
```

### Examples

```bash
# Scan pubspec.lock in the current directory:
dart_audit

# Scan a specific lockfile:
dart_audit --lockfile path/to/pubspec.lock

# Show all packages (clean + vulnerable):
dart_audit --verbose

# Report findings but never fail the build (CI reporting mode):
dart_audit --exit-zero
```

---

## Sample output

```
Scanning 42 packages against OSV.dev... done.

dart_audit — OSV.dev scan · 42 packages checked
────────────────────────────────────────────────────────────

[CRITICAL] some_package 1.0.0
  CVE-2024-12345 · GHSA-xxxx-yyyy-zzzz
  Remote code execution via malformed input
  Fixed in: 1.0.1
  https://osv.dev/vulnerability/CVE-2024-12345

────────────────────────────────────────────────────────────
Vulnerabilities found: 1 critical, 0 high, 0 medium, 0 low
Run `dart pub upgrade` or pin to the fixed version to resolve.
```

When no vulnerabilities are found:

```
Scanning 51 packages against OSV.dev... done.

dart_audit — OSV.dev scan · 51 packages checked
────────────────────────────────────────────────────────────

✔ No known vulnerabilities found in 51 packages.
────────────────────────────────────────────────────────────
No vulnerabilities found. 51 packages scanned.
```

---

## CI/CD integration

### GitHub Actions

```yaml
steps:
  - uses: actions/checkout@v4

  - uses: dart-lang/setup-dart@v1
    with:
      sdk: stable

  - name: Install dependencies
    run: dart pub get

  - name: Security audit
    run: |
      dart pub global activate dart_audit
      dart_audit
```

The step fails automatically (exit code 1) if any vulnerability is found.  
Use `dart_audit --exit-zero` to report without failing.

### GitLab CI

```yaml
security-audit:
  script:
    - dart pub global activate dart_audit
    - dart_audit
```

---

## How it works

1. **Parses `pubspec.lock`** — extracts the exact name and version of every `hosted` package (i.e., packages from pub.dev).
2. **Queries OSV.dev** — sends a single `POST /v1/querybatch` request with all packages to `api.osv.dev`. Batches in groups of 100 to stay within API limits.
3. **Renders the report** — groups results by severity (CRITICAL → HIGH → MEDIUM → LOW), shows CVE/GHSA IDs, summaries, and available fix versions.
4. **Exits with code 1** if any vulnerability is found, so CI pipelines fail automatically.

OSV.dev is maintained by Google and is the same underlying database that powers GitHub's Dependabot security alerts.

---

## Limitations

- Only scans packages from `pub.dev` (hosted source). Git or path dependencies are skipped.
- Requires an active internet connection to reach `api.osv.dev`.
- Vulnerability data depends on OSV.dev's coverage — not all CVEs may be indexed.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
