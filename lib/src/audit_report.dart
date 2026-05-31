import 'dart:io';

import 'osv_client.dart';

// ANSI color codes — skipped when stdout is not a terminal (CI pipes).
bool get _colorize => stdout.hasTerminal;

String _red(String s) => _colorize ? '\x1B[31m$s\x1B[0m' : s;
String _yellow(String s) => _colorize ? '\x1B[33m$s\x1B[0m' : s;
String _cyan(String s) => _colorize ? '\x1B[36m$s\x1B[0m' : s;
String _green(String s) => _colorize ? '\x1B[32m$s\x1B[0m' : s;
String _bold(String s) => _colorize ? '\x1B[1m$s\x1B[0m' : s;
String _dim(String s) => _colorize ? '\x1B[2m$s\x1B[0m' : s;

/// Prints the full audit report to stdout and returns the number of
/// vulnerable packages found (useful for setting a CI exit code).
int printReport(
  List<PackageAuditResult> results, {
  bool verbose = false,
}) {
  final vulnerable = results.where((r) => r.isVulnerable).toList();
  final clean = results.where((r) => !r.isVulnerable).toList();

  final totalVulns =
      vulnerable.fold(0, (sum, r) => sum + r.vulnerabilities.length);

  // ── Header ─────────────────────────────────────────────────────────────────
  stdout.writeln();
  stdout.writeln(
    _bold('dart_audit') +
        _dim(' — OSV.dev scan · ${results.length} packages checked'),
  );
  stdout.writeln(_dim('─' * 60));

  // ── Vulnerabilities ────────────────────────────────────────────────────────
  if (vulnerable.isEmpty) {
    stdout.writeln();
    stdout.writeln(
      _green('✔ No known vulnerabilities found in ${results.length} packages.'),
    );
  } else {
    stdout.writeln();
    for (final result in vulnerable) {
      _printVulnerablePackage(result);
    }
  }

  // ── Clean packages (verbose only) ──────────────────────────────────────────
  if (verbose && clean.isNotEmpty) {
    stdout.writeln(_dim('─' * 60));
    stdout.writeln(_dim('Clean packages (${clean.length}):'));
    for (final r in clean) {
      stdout.writeln(_dim('  ✔ ${r.package.name} ${r.package.version}'));
    }
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  stdout.writeln();
  stdout.writeln(_dim('─' * 60));

  if (vulnerable.isEmpty) {
    stdout.writeln(
      '${_green(_bold('No vulnerabilities found.'))} ${results.length} packages scanned.',
    );
  } else {
    final criticalCount = _countBySeverity(vulnerable, OsvSeverity.critical);
    final highCount = _countBySeverity(vulnerable, OsvSeverity.high);
    final mediumCount = _countBySeverity(vulnerable, OsvSeverity.medium);
    final lowCount = _countBySeverity(vulnerable, OsvSeverity.low);
    final unknownCount = _countBySeverity(vulnerable, OsvSeverity.unknown);

    stdout.writeln(
      _red(_bold('$totalVulns ${_plural(totalVulns, 'vulnerability', 'vulnerabilities')} '
          'found across ${vulnerable.length} ${_plural(vulnerable.length, 'package', 'packages')}.')),
    );

    final parts = <String>[];
    if (criticalCount > 0) parts.add(_red('$criticalCount critical'));
    if (highCount > 0) parts.add(_red('$highCount high'));
    if (mediumCount > 0) parts.add(_yellow('$mediumCount medium'));
    if (lowCount > 0) parts.add('$lowCount low');
    if (unknownCount > 0) parts.add(_dim('$unknownCount unknown severity'));

    if (parts.isNotEmpty) {
      stdout.writeln('  ${parts.join(' · ')}');
    }

    stdout.writeln();
    stdout.writeln(
      '${_dim('Run ')}dart pub upgrade${_dim(' to update dependencies, or pin a safe version in pubspec.yaml.')}',
    );
  }

  stdout.writeln();
  return vulnerable.length;
}

void _printVulnerablePackage(PackageAuditResult result) {
  final pkg = result.package;
  stdout.writeln(
    '${_bold(pkg.name)} ${pkg.version}${_dim(pkg.isDirect ? ' (direct)' : ' (transitive)')}',
  );

  for (final vuln in result.vulnerabilities) {
    final severityLabel = _severityLabel(vuln.severity);
    final aliasStr = vuln.aliases.isNotEmpty
        ? _dim(' · ${vuln.aliases.join(', ')}')
        : '';

    stdout.writeln('  $severityLabel ${_bold(vuln.id)}$aliasStr');
    stdout.writeln('  ${_dim(vuln.summary)}');

    if (vuln.fixedVersion != null) {
      stdout.writeln(
        '  ${_green('Fix:')} upgrade to ${_bold(vuln.fixedVersion!)} or later',
      );
    } else {
      stdout.writeln('  ${_yellow('No fix available yet.')}');
    }

    stdout.writeln('  ${_dim(vuln.detailsUrl)}');
    stdout.writeln();
  }
}

String _severityLabel(OsvSeverity severity) => switch (severity) {
      OsvSeverity.critical => _red('[CRITICAL]'),
      OsvSeverity.high => _red('[HIGH]    '),
      OsvSeverity.medium => _yellow('[MEDIUM]  '),
      OsvSeverity.low => _cyan('[LOW]     '),
      OsvSeverity.unknown => _dim('[UNKNOWN] '),
    };

int _countBySeverity(
  List<PackageAuditResult> results,
  OsvSeverity severity,
) =>
    results.fold(
      0,
      (sum, r) =>
          sum + r.vulnerabilities.where((v) => v.severity == severity).length,
    );

String _plural(int count, String singular, String plural) =>
    count == 1 ? singular : plural;
