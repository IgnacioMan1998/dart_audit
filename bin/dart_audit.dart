import 'dart:io';

import 'package:args/args.dart';
import 'package:yaml/yaml.dart';

import 'package:dart_audit/src/audit_report.dart';
import 'package:dart_audit/src/lockfile_parser.dart';
import 'package:dart_audit/src/osv_client.dart';

String _readVersion() {
  try {
    final pubspec = loadYaml(File('pubspec.yaml').readAsStringSync()) as YamlMap;
    return pubspec['version'] as String? ?? '0.0.0';
  } catch (_) {
    return '0.0.0';
  }
}

void main(List<String> args) async {
  final version = _readVersion();

  final parser = ArgParser()
    ..addOption(
      'lockfile',
      abbr: 'l',
      help: 'Path to pubspec.lock.',
      defaultsTo: 'pubspec.lock',
    )
    ..addOption(
      'format',
      abbr: 'f',
      help: 'Output format.',
      allowed: ['text', 'json'],
      allowedHelp: {
        'text': 'Human-readable text (default).',
        'json': 'Machine-readable JSON (useful for CI/CD pipelines).',
      },
      defaultsTo: 'text',
    )
    ..addOption(
      'min-severity',
      help: 'Minimum severity level to report and count as a failure.',
      allowed: ['critical', 'high', 'medium', 'low', 'unknown'],
      allowedHelp: {
        'critical': 'Only critical vulnerabilities.',
        'high': 'High and critical.',
        'medium': 'Medium, high, and critical.',
        'low': 'All except unknown.',
        'unknown': 'All vulnerabilities (default).',
      },
      defaultsTo: 'unknown',
    )
    ..addMultiOption(
      'ignore',
      abbr: 'i',
      help: 'Vulnerability IDs to ignore (e.g. GHSA-xxxx or CVE-yyyy-nnnn). '
          'Can be specified multiple times.',
      valueHelp: 'ID',
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      help: 'Show all packages, including clean ones.',
      negatable: false,
    )
    ..addFlag(
      'no-color',
      help: 'Disable ANSI color output.',
      negatable: false,
    )
    ..addFlag(
      'exit-zero',
      help: 'Always exit 0, even when vulnerabilities are found (for CI reporting).',
      negatable: false,
    )
    ..addFlag(
      'version',
      help: 'Print version and exit.',
      negatable: false,
    )
    ..addFlag(
      'help',
      abbr: 'h',
      help: 'Show this help.',
      negatable: false,
    );

  late final ArgResults opts;
  try {
    opts = parser.parse(args);
  } on FormatException catch (e) {
    stderr.writeln('Error: ${e.message}');
    stderr.writeln(parser.usage);
    exit(64); // EX_USAGE
  }

  if (opts['help'] as bool) {
    stdout.writeln('dart_audit $version — Dart/Flutter security audit tool');
    stdout.writeln();
    stdout.writeln('Scans pubspec.lock against the OSV.dev vulnerability database.');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit [options]');
    stdout.writeln();
    stdout.writeln(parser.usage);
    stdout.writeln();
    stdout.writeln('Examples:');
    stdout.writeln('  dart_audit                          # scan pubspec.lock in current directory');
    stdout.writeln('  dart_audit -l path/to/pubspec.lock');
    stdout.writeln('  dart_audit --verbose                # also list clean packages');
    stdout.writeln('  dart_audit --min-severity high      # only report high/critical');
    stdout.writeln('  dart_audit --ignore GHSA-xxxx-xxxx-xxxx --ignore CVE-2024-12345');
    stdout.writeln('  dart_audit --format json            # machine-readable output');
    stdout.writeln('  dart_audit --exit-zero              # for CI — report only, never fail build');
    exit(0);
  }

  if (opts['version'] as bool) {
    stdout.writeln('dart_audit $version');
    exit(0);
  }

  final lockfilePath = opts['lockfile'] as String;
  final format = opts['format'] as String;
  final verbose = opts['verbose'] as bool;
  final noColor = opts['no-color'] as bool;
  final exitZero = opts['exit-zero'] as bool;
  final ignoredIds = (opts['ignore'] as List<String>).toSet();
  final minSeverity = OsvSeverity.values.firstWhere(
    (s) => s.name == (opts['min-severity'] as String),
    orElse: () => OsvSeverity.unknown,
  );

  if (noColor) disableColor();

  // ── Parse lockfile ──────────────────────────────────────────────────────────
  final ParsedLockfile lockfile;
  try {
    lockfile = parseLockfile(lockfilePath);
  } on FileSystemException catch (e) {
    stderr.writeln('Error: ${e.message}');
    exit(1);
  } on FormatException catch (e) {
    stderr.writeln('Error parsing $lockfilePath: ${e.message}');
    exit(1);
  }

  final packages = lockfile.hostedPackages;

  if (packages.isEmpty) {
    stdout.writeln('No hosted packages found in $lockfilePath.');
    exit(0);
  }

  // ── Query OSV ───────────────────────────────────────────────────────────────
  final totalBatches = (packages.length / 100).ceil();
  final multiplesBatches = totalBatches > 1;

  if (format == 'text') {
    if (multiplesBatches) {
      stdout.write('Scanning ${packages.length} packages against OSV.dev (batch 1/$totalBatches)...');
    } else {
      stdout.write('Scanning ${packages.length} packages against OSV.dev...');
    }
  }

  var batchNum = 1;
  final List<PackageAuditResult> results;
  try {
    results = await queryOsv(
      packages,
      onBatchProgress: (done, total) {
        if (format != 'text' || !multiplesBatches) return;
        batchNum++;
        if (done < total) {
          stdout.write('\rScanning $total packages against OSV.dev (batch $batchNum/$totalBatches)...');
        }
      },
    );
    if (format == 'text') stdout.writeln(' done.');
  } catch (e) {
    if (format == 'text') stdout.writeln();
    stderr.writeln('Error contacting OSV.dev: $e');
    exit(1);
  }

  // ── Print report ────────────────────────────────────────────────────────────
  final skippedNames = lockfile.skippedPackages.map((p) => '${p.name} (${p.source})').toList();

  final int vulnerableCount;
  if (format == 'json') {
    vulnerableCount = printJsonReport(
      results,
      minSeverity: minSeverity,
      ignoredIds: ignoredIds,
    );
  } else {
    vulnerableCount = printReport(
      results,
      verbose: verbose,
      minSeverity: minSeverity,
      ignoredIds: ignoredIds,
      skippedPackages: skippedNames,
    );
  }

  // Exit 1 if vulnerabilities found (unless --exit-zero).
  exit(exitZero ? 0 : (vulnerableCount > 0 ? 1 : 0));
}

