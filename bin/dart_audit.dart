import 'dart:io';

import 'package:args/args.dart';

import 'package:dart_audit/src/audit_report.dart';
import 'package:dart_audit/src/lockfile_parser.dart';
import 'package:dart_audit/src/osv_client.dart';

const _version = '0.1.0';

void main(List<String> args) async {
  final parser = ArgParser()
    ..addOption(
      'lockfile',
      abbr: 'l',
      help: 'Path to pubspec.lock.',
      defaultsTo: 'pubspec.lock',
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      help: 'Show all packages, including clean ones.',
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
    stdout.writeln('dart_audit $_version — Dart/Flutter security audit tool');
    stdout.writeln();
    stdout.writeln('Scans pubspec.lock against the OSV.dev vulnerability database.');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit [options]');
    stdout.writeln();
    stdout.writeln(parser.usage);
    stdout.writeln();
    stdout.writeln('Examples:');
    stdout.writeln('  dart_audit                  # scan pubspec.lock in current directory');
    stdout.writeln('  dart_audit -l path/to/pubspec.lock');
    stdout.writeln('  dart_audit --verbose        # also list clean packages');
    stdout.writeln('  dart_audit --exit-zero      # for CI — report only, never fail build');
    exit(0);
  }

  if (opts['version'] as bool) {
    stdout.writeln('dart_audit $_version');
    exit(0);
  }

  final lockfilePath = opts['lockfile'] as String;
  final verbose = opts['verbose'] as bool;
  final exitZero = opts['exit-zero'] as bool;

  // ── Parse lockfile ──────────────────────────────────────────────────────────
  final List<LockedPackage> packages;
  try {
    packages = parseLockfile(lockfilePath);
  } on FileSystemException catch (e) {
    stderr.writeln('Error: ${e.message}');
    exit(1);
  } on FormatException catch (e) {
    stderr.writeln('Error parsing $lockfilePath: ${e.message}');
    exit(1);
  }

  if (packages.isEmpty) {
    stdout.writeln('No hosted packages found in $lockfilePath.');
    exit(0);
  }

  stdout.write(
    'Scanning ${packages.length} packages against OSV.dev...',
  );

  // ── Query OSV ───────────────────────────────────────────────────────────────
  final List<PackageAuditResult> results;
  try {
    results = await queryOsv(packages);
    stdout.writeln(' done.');
  } catch (e) {
    stdout.writeln();
    stderr.writeln('Error contacting OSV.dev: $e');
    exit(1);
  }

  // ── Print report ────────────────────────────────────────────────────────────
  final vulnerableCount = printReport(results, verbose: verbose);

  // Exit 1 if vulnerabilities found (unless --exit-zero).
  exit(exitZero ? 0 : (vulnerableCount > 0 ? 1 : 0));
}

