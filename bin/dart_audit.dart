import 'dart:io';

import 'package:args/args.dart';
import 'package:yaml/yaml.dart';

import 'package:dart_audit/src/audit_report.dart';
import 'package:dart_audit/src/color_output.dart' as color;
import 'package:dart_audit/src/inspection_report_printer.dart';
import 'package:dart_audit/src/inspector/package_downloader.dart';
import 'package:dart_audit/src/inspector/package_inspector.dart';
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

  // ── Top-level parser ────────────────────────────────────────────────────────
  final globalParser = ArgParser()
    ..addFlag('no-color', help: 'Disable ANSI color output.', negatable: false)
    ..addFlag('version', help: 'Print version and exit.', negatable: false)
    ..addFlag('help', abbr: 'h', help: 'Show this help.', negatable: false);

  // ── `audit` sub-command (default) ───────────────────────────────────────────
  final auditParser = ArgParser()
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
      help: 'Vulnerability IDs to ignore (repeatable). E.g. --ignore GHSA-xxxx',
      valueHelp: 'ID',
    )
    ..addFlag('verbose', abbr: 'v', help: 'Show all packages, including clean ones.', negatable: false)
    ..addFlag('no-color', help: 'Disable ANSI color output.', negatable: false)
    ..addFlag('exit-zero', help: 'Always exit 0 even when vulnerabilities are found.', negatable: false)
    ..addFlag('help', abbr: 'h', help: 'Show this help.', negatable: false);

  // ── `inspect` sub-command ───────────────────────────────────────────────────
  final inspectParser = ArgParser()
    ..addOption(
      'format',
      abbr: 'f',
      help: 'Output format.',
      allowed: ['text', 'json'],
      defaultsTo: 'text',
    )
    ..addFlag('exit-zero', help: 'Always exit 0 even when package is suspicious.', negatable: false)
    ..addFlag('no-color', help: 'Disable ANSI color output.', negatable: false)
    ..addFlag('help', abbr: 'h', help: 'Show this help.', negatable: false);

  globalParser
    ..addCommand('audit', auditParser)
    ..addCommand('inspect', inspectParser);

  // ── Parse ───────────────────────────────────────────────────────────────────
  late final ArgResults global;
  try {
    global = globalParser.parse(args);
  } on FormatException catch (e) {
    stderr.writeln('Error: ${e.message}');
    _printTopLevelHelp(version, globalParser);
    exit(64);
  }

  if (global['version'] as bool) {
    stdout.writeln('dart_audit $version');
    exit(0);
  }

  final command = global.command;

  if (command == null || global['help'] as bool) {
    _printTopLevelHelp(version, globalParser);
    exit(0);
  }

  // Apply --no-color early (global or sub-command level).
  if ((global['no-color'] as bool) || (command['no-color'] as bool? ?? false)) {
    color.disableColor();
  }

  switch (command.name) {
    case 'inspect':
      await _runInspect(command, inspectParser, version);
    default:
      // 'audit' is also the default when no sub-command name matches.
      await _runAudit(command.name == 'audit' ? command : command, auditParser, version);
  }
}

// ── audit sub-command ──────────────────────────────────────────────────────────

Future<void> _runAudit(ArgResults opts, ArgParser parser, String version) async {
  if (opts['help'] as bool) {
    stdout.writeln('dart_audit $version audit — Scan pubspec.lock against OSV.dev');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit audit [options]');
    stdout.writeln();
    stdout.writeln(parser.usage);
    stdout.writeln();
    stdout.writeln('Examples:');
    stdout.writeln('  dart_audit audit');
    stdout.writeln('  dart_audit audit -l path/to/pubspec.lock');
    stdout.writeln('  dart_audit audit --min-severity high');
    stdout.writeln('  dart_audit audit --ignore GHSA-xxxx-xxxx-xxxx');
    stdout.writeln('  dart_audit audit --format json');
    exit(0);
  }

  final lockfilePath = opts['lockfile'] as String;
  final format = opts['format'] as String;
  final verbose = opts['verbose'] as bool;
  final exitZero = opts['exit-zero'] as bool;
  final ignoredIds = (opts['ignore'] as List<String>).toSet();
  final minSeverity = OsvSeverity.values.firstWhere(
    (s) => s.name == (opts['min-severity'] as String),
    orElse: () => OsvSeverity.unknown,
  );

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

  final totalBatches = (packages.length / 100).ceil();
  final multiBatch = totalBatches > 1;

  if (format == 'text') {
    stdout.write(multiBatch
        ? 'Scanning ${packages.length} packages against OSV.dev (batch 1/$totalBatches)...'
        : 'Scanning ${packages.length} packages against OSV.dev...');
  }

  var batchNum = 1;
  final List<PackageAuditResult> results;
  try {
    results = await queryOsv(
      packages,
      onBatchProgress: (done, total) {
        if (format != 'text' || !multiBatch) return;
        batchNum++;
        if (done < total) {
          stdout.write(
            '\rScanning $total packages against OSV.dev (batch $batchNum/$totalBatches)...',
          );
        }
      },
    );
    if (format == 'text') stdout.writeln(' done.');
  } catch (e) {
    if (format == 'text') stdout.writeln();
    stderr.writeln('Error contacting OSV.dev: $e');
    exit(1);
  }

  final skippedNames =
      lockfile.skippedPackages.map((p) => '${p.name} (${p.source})').toList();

  final int vulnerableCount;
  if (format == 'json') {
    vulnerableCount = printJsonReport(results, minSeverity: minSeverity, ignoredIds: ignoredIds);
  } else {
    vulnerableCount = printReport(
      results,
      verbose: verbose,
      minSeverity: minSeverity,
      ignoredIds: ignoredIds,
      skippedPackages: skippedNames,
    );
  }

  exit(exitZero ? 0 : (vulnerableCount > 0 ? 1 : 0));
}

// ── inspect sub-command ────────────────────────────────────────────────────────

Future<void> _runInspect(ArgResults opts, ArgParser parser, String version) async {
  if (opts['help'] as bool) {
    stdout.writeln('dart_audit $version inspect — Static source analysis of a pub.dev package');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit inspect <package> <version> [options]');
    stdout.writeln();
    stdout.writeln(parser.usage);
    stdout.writeln();
    stdout.writeln('Examples:');
    stdout.writeln('  dart_audit inspect http 1.2.0');
    stdout.writeln('  dart_audit inspect some_package 0.0.1 --format json');
    stdout.writeln('  dart_audit inspect some_package 0.0.1 --exit-zero');
    exit(0);
  }

  final rest = opts.rest;
  if (rest.length < 2) {
    stderr.writeln('Error: inspect requires <package> and <version> arguments.');
    stderr.writeln('Usage: dart_audit inspect <package> <version>');
    exit(64);
  }

  final packageName = rest[0];
  final packageVersion = rest[1];
  final format = opts['format'] as String;
  final exitZero = opts['exit-zero'] as bool;

  if (format == 'text') {
    stdout.writeln(
      'Inspecting $packageName $packageVersion — downloading source...',
    );
  }

  final inspector = PackageInspector();

  final InspectionReport report;
  try {
    report = await inspector.inspect(
      packageName,
      packageVersion,
      onStatus: format == 'text' ? (s) => stdout.writeln('  $s') : null,
    );
  } on PackageNotFoundException catch (e) {
    stderr.writeln('Error: $e');
    exit(1);
  } catch (e) {
    stderr.writeln('Error during inspection: $e');
    exit(1);
  }

  if (format == 'json') {
    printJsonInspectionReport(report);
  } else {
    printInspectionReport(report);
  }

  exit(exitZero ? 0 : (report.isSuspicious ? 1 : 0));
}

// ── Help ───────────────────────────────────────────────────────────────────────

void _printTopLevelHelp(String version, ArgParser parser) {
  stdout.writeln('dart_audit $version — Dart/Flutter supply-chain security tool');
  stdout.writeln();
  stdout.writeln('Commands:');
  stdout.writeln('  audit     Scan pubspec.lock against OSV.dev for known CVEs (default)');
  stdout.writeln('  inspect   Static source analysis of a pub.dev package for malicious patterns');
  stdout.writeln();
  stdout.writeln('Global options:');
  stdout.writeln(parser.usage);
  stdout.writeln();
  stdout.writeln('Run `dart_audit <command> --help` for command-specific options.');
  stdout.writeln();
  stdout.writeln('Examples:');
  stdout.writeln('  dart_audit audit                         # scan current project');
  stdout.writeln('  dart_audit audit --format json           # JSON output for CI');
  stdout.writeln('  dart_audit audit --min-severity high     # only high/critical');
  stdout.writeln('  dart_audit inspect http 1.2.0            # inspect package source');
}


