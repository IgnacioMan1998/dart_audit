# dart_audit

[![pub version](https://img.shields.io/pub/v/dart_audit)](https://pub.dev/packages/dart_audit)
[![OSV.dev](https://img.shields.io/badge/powered%20by-OSV.dev-blue)](https://osv.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Security toolkit for Dart and Flutter projects — two commands, two layers of defence:

| Command                              | What it does                                                                                                                       |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `dart_audit audit`                   | Checks every dependency in `pubspec.lock` against the [OSV.dev](https://osv.dev) vulnerability database                            |
| `dart_audit inspect <pkg> <version>` | Downloads a package from pub.dev and statically analyses its Dart source for suspicious patterns before you add it to your project |

---

## Features

### `audit` — CVE / advisory scanning

- Scans **all** packages (direct and transitive) from `pubspec.lock`
- Batched requests to `api.osv.dev` — fast, no API key needed
- 30 s timeout with automatic retries (exponential back-off, up to 3 attempts)
- CVSS severity classification: CRITICAL / HIGH / MEDIUM / LOW
- Shows CVE / GHSA aliases, summary, and available fix version
- Filter by minimum severity (`--min-severity high`)
- Suppress known findings (`--ignore CVE-2024-12345`)
- `--format json` for machine-readable output
- Warns about git / path / sdk dependencies that cannot be scanned
- Exit code `1` on findings — integrates directly into CI/CD pipelines
- `--exit-zero` for reporting-only mode

### `inspect` — static source analysis (supply-chain defence)

- Downloads the package archive from pub.dev and extracts `.dart` files
- **Regex scanner** — 14 rules across 7 categories:
  - Hard-coded URLs to unknown hosts
  - Raw socket / TCP connections
  - `Process.run` / shell injection
  - Sensitive file-system access (`/etc/passwd`, `~/.ssh`, etc.)
  - Hex encoding, Base64 eval, Unicode escapes, char-code concatenation (obfuscation)
  - Crypto-mining patterns
  - Backdoor / reverse-shell patterns
  - Data exfiltration markers
- **Shannon entropy scanner** — flags strings with unusually high entropy (potential obfuscated payloads or embedded secrets)
- Risk score 0–100 with labels: CLEAN / LOW RISK / SUSPICIOUS / HIGH RISK
- `--format json` for machine-readable output
- Exit code `1` when the package is flagged as SUSPICIOUS or worse

---

## Installation

### As a global tool (recommended)

```bash
dart pub global activate dart_audit
```

Make sure `~/.pub-cache/bin` is in your `PATH`:

```bash
export PATH="$PATH:$HOME/.pub-cache/bin"
```

### As a dev dependency (project-local)

```yaml
dev_dependencies:
  dart_audit: ^0.2.0
```

```bash
dart run dart_audit audit
```

---

## Usage

```
Usage: dart_audit <command> [options]

Commands:
  audit      Scan pubspec.lock against the OSV.dev vulnerability database (default).
  inspect    Statically analyse a pub.dev package before adding it to your project.

Global options:
  --no-color    Disable ANSI colours.
  --version     Print version and exit.
  -h, --help    Show this help.
```

### `audit`

```
Usage: dart_audit audit [options]

-l, --lockfile         Path to pubspec.lock (default: "pubspec.lock").
-f, --format           Output format: text (default) or json.
    --min-severity     Only report findings at or above this level (low/medium/high/critical).
-i, --ignore           Ignore a specific CVE/GHSA ID. Can be repeated.
-v, --verbose          Show all packages, including clean ones.
    --exit-zero        Always exit 0, even when vulnerabilities are found.
-h, --help             Show this help.
```

#### Examples

```bash
# Scan the current project:
dart_audit audit

# Scan a specific lockfile:
dart_audit audit --lockfile path/to/pubspec.lock

# Only report HIGH and CRITICAL findings:
dart_audit audit --min-severity high

# Suppress a known false-positive:
dart_audit audit --ignore GHSA-xxxx-yyyy-zzzz

# Machine-readable output:
dart_audit audit --format json

# Report without failing the build:
dart_audit audit --exit-zero
```

#### Sample output

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

---

### `inspect`

```
Usage: dart_audit inspect <package> <version> [options]

-f, --format      Output format: text (default) or json.
    --exit-zero   Always exit 0, even when the package is flagged.
-h, --help        Show this help.
```

#### Examples

```bash
# Inspect a package before adding it:
dart_audit inspect http 1.2.0

# Get JSON output:
dart_audit inspect some_package 0.3.1 --format json

# Use in CI without failing the build:
dart_audit inspect new_dep 2.0.0 --exit-zero
```

#### Sample output

```
Inspecting some_package 0.3.1...
Downloading package source... done.
Scanning 12 Dart files...

dart_audit — inspect · some_package 0.3.1
────────────────────────────────────────────────────────────

Regex findings (3):

  [CRITICAL] lib/src/native.dart:42
  Rule: PROCESS_RUN
  Executes a system process via Process.run/start
  › Process.run('curl', ['-d', data, exfilUrl])

  [HIGH] lib/src/net.dart:18
  Rule: RAW_SOCKET
  Opens a raw TCP socket
  › final socket = await Socket.connect(host, port);

  [MEDIUM] lib/src/utils.dart:7
  Rule: HEX_ENCODING
  Large hex-encoded string literal — possible obfuscated payload
  › const _payload = '41424344...';

Entropy findings (1):

  lib/src/utils.dart:31  entropy=5.82 bits  [HIGH]
  › 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q='

────────────────────────────────────────────────────────────
Risk score: 75 / 100  ⚠ HIGH RISK
```

---

## CI/CD integration

### GitHub Actions — audit + inspect

```yaml
steps:
  - uses: actions/checkout@v4

  - uses: dart-lang/setup-dart@v1
    with:
      sdk: stable

  - name: Install dart_audit
    run: dart pub global activate dart_audit

  - name: Audit known CVEs
    run: dart_audit audit

  - name: Inspect a new dependency before adding it
    run: dart_audit inspect http 1.2.0
```

Both steps fail automatically (exit code 1) on findings.  
Use `--exit-zero` to report without blocking the pipeline.

### GitLab CI

```yaml
security-audit:
  script:
    - dart pub global activate dart_audit
    - dart_audit audit
```

---

## How it works

### `audit`

1. Parses `pubspec.lock` — extracts the exact name and version of every `hosted` package.
2. Queries `api.osv.dev/v1/querybatch` in batches of 100 packages per request.
3. Parses CVSS scores from the OSV response (v3 → v2 → database-specific fallback).
4. Renders a report grouped by severity; exits with code 1 if any findings pass the filter.

### `inspect`

1. Downloads the `.tar.gz` archive from `pub.dev/api/packages/<name>/versions/<version>`.
2. Extracts only `.dart` files to a temporary directory (cleaned up automatically).
3. Runs the regex scanner and entropy scanner in parallel.
4. Calculates a weighted risk score (CRITICAL regex: 40 pts, HIGH: 20 pts, MEDIUM: 10 pts; HIGH entropy: 15 pts, MEDIUM: 5 pts), clamped to 0–100.
5. Exits with code 1 if the risk score ≥ 30 (SUSPICIOUS or worse).

---

## Limitations

- `audit` only scans packages from pub.dev (`hosted` source). Git, path, and SDK dependencies are skipped (a warning is shown).
- `inspect` requires an active internet connection to download the package archive.
- Vulnerability data depends on OSV.dev coverage — not all CVEs may be indexed.
- The regex and entropy scanners produce heuristic results. Review findings manually before rejecting a package.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
