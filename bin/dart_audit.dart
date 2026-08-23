import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:yaml/yaml.dart';

import 'package:dart_audit/src/audit_report.dart';
import 'package:dart_audit/src/color_output.dart' as color;
import 'package:dart_audit/src/inspection_report_printer.dart';
import 'package:dart_audit/src/inspector/package_downloader.dart';
import 'package:dart_audit/src/inspector/package_inspector.dart';
import 'package:dart_audit/src/inspector/trust_scorer.dart';
import 'package:dart_audit/src/inspector/typosquat_detector.dart';
import 'package:dart_audit/src/inspector/confusion_detector.dart';
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

  // ── `trust` sub-command ─────────────────────────────────────────────────────
  final trustParser = ArgParser()
    ..addOption(
      'format',
      abbr: 'f',
      help: 'Output format.',
      allowed: ['text', 'json'],
      defaultsTo: 'text',
    )
    ..addFlag('help', abbr: 'h', help: 'Show this help.', negatable: false);

  // ── `typosquat` sub-command ─────────────────────────────────────────────────
  final typosquatParser = ArgParser()
    ..addOption(
      'pubspec',
      help: 'Path to pubspec.yaml to analyze.',
      defaultsTo: 'pubspec.yaml',
    )
    ..addOption(
      'format',
      abbr: 'f',
      help: 'Output format.',
      allowed: ['text', 'json'],
      defaultsTo: 'text',
    )
    ..addFlag('help', abbr: 'h', help: 'Show this help.', negatable: false);

  globalParser
    ..addCommand('audit', auditParser)
    ..addCommand('inspect', inspectParser)
    ..addCommand('trust', trustParser)
    ..addCommand('typosquat', typosquatParser);

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
    case 'trust':
      await _runTrust(command, trustParser, version);
    case 'typosquat':
      await _runTyposquat(command, typosquatParser, version);
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
    stdout.writeln('dart_audit $version inspect — Deep security analysis of a pub.dev package');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit inspect <package> <version> [options]');
    stdout.writeln();
    stdout.writeln('Detection layers:');
    stdout.writeln('  1. Regex scanner — 14 rules: process execution, network, crypto-mining,');
    stdout.writeln('     obfuscation, backdoors, data exfiltration');
    stdout.writeln('  2. Entropy scanner — high-entropy string literals (obfuscation/encryption)');
    stdout.writeln('  3. Unicode scanner — Trojan Source (CVE-2021-42574), GlassWorm PUA carriers,');
    stdout.writeln('     invisible bidi characters, homoglyphs');
    stdout.writeln('  4. Trust scorer — package age, popularity, publisher verification,');
    stdout.writeln('     fresh release detection (prevents newly-published attacks)');
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

// ── trust sub-command ──────────────────────────────────────────────────────────

Future<void> _runTrust(ArgResults opts, ArgParser parser, String version) async {
  if (opts['help'] as bool) {
    stdout.writeln('dart_audit $version trust — Assess package trust metadata from pub.dev');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit trust <package> [options]');
    stdout.writeln();
    stdout.writeln('Checks:');
    stdout.writeln('  • Package age and freshness (recently published = higher risk)');
    stdout.writeln('  • Community endorsement (likes, downloads)');
    stdout.writeln('  • Publisher verification status');
    stdout.writeln('  • Quality score (pub points)');
    stdout.writeln();
    stdout.writeln(parser.usage);
    exit(0);
  }

  final rest = opts.rest;
  if (rest.isEmpty) {
    stderr.writeln('Error: trust requires a package name argument.');
    stderr.writeln('Usage: dart_audit trust <package>');
    exit(64);
  }

  final packageName = rest[0];
  final format = opts['format'] as String;

  if (format == 'text') {
    stdout.writeln('Checking trust metadata for $packageName...');
  }

  final scorer = TrustScorer();
  final info = await scorer.assess(packageName);

  if (info == null) {
    stderr.writeln('Error: Package "$packageName" not found on pub.dev.');
    exit(1);
  }

  if (format == 'json') {
    stdout.writeln(const JsonEncoder.withIndent('  ').convert(info.toJson()));
  } else {
    _printTrustReport(info);
  }

  exit(info.isTrusted ? 0 : 1);
}

void _printTrustReport(PackageTrustInfo info) {
  stdout.writeln();
  stdout.writeln('dart_audit — Trust Assessment · ${info.packageName} ${info.version ?? ""}');
  stdout.writeln('─' * 60);

  if (info.createdAt != null) {
    final ageDays = DateTime.now().toUtc().difference(info.createdAt!).inDays;
    stdout.writeln('  Created: ${info.createdAt!.toIso8601String().substring(0, 10)} ($ageDays days ago)');
  }
  if (info.lastPublishedAt != null) {
    final hoursSince = DateTime.now().toUtc().difference(info.lastPublishedAt!).inHours;
    stdout.writeln('  Last published: ${info.lastPublishedAt!.toIso8601String().substring(0, 16)} '
        '(${hoursSince}h ago)');
  }
  if (info.likeCount != null) stdout.writeln('  Likes: ${info.likeCount}');
  if (info.downloadCount30Days != null) stdout.writeln('  Downloads (30d): ${info.downloadCount30Days}');
  if (info.grantedPoints != null && info.maxPoints != null) {
    stdout.writeln('  Pub points: ${info.grantedPoints}/${info.maxPoints}');
  }
  if (info.publisher != null && info.publisher!.isNotEmpty) {
    final status = info.isVerifiedPublisher ? 'verified' : 'UNVERIFIED';
    stdout.writeln('  Publisher: ${info.publisher} ($status)');
  } else {
    stdout.writeln('  Publisher: none');
  }

  stdout.writeln();
  stdout.writeln('─' * 60);

  if (info.findings.isEmpty) {
    stdout.writeln('  ✔ No trust concerns detected.');
  } else {
    for (final f in info.findings) {
      final label = switch (f.severity) {
        'CRITICAL' => '\x1B[31m[CRITICAL]\x1B[0m',
        'HIGH' => '\x1B[31m[HIGH]    \x1B[0m',
        'MEDIUM' => '\x1B[33m[MEDIUM]  \x1B[0m',
        _ => '\x1B[2m[LOW]     \x1B[0m',
      };
      stdout.writeln('  $label ${f.description}');
    }
  }

  stdout.writeln('─' * 60);
  stdout.writeln();
}

// ── typosquat sub-command ──────────────────────────────────────────────────────

Future<void> _runTyposquat(ArgResults opts, ArgParser parser, String version) async {
  if (opts['help'] as bool) {
    stdout.writeln('dart_audit $version typosquat — Detect typosquatting and dependency confusion');
    stdout.writeln();
    stdout.writeln('Usage: dart_audit typosquat [options]');
    stdout.writeln();
    stdout.writeln('Analysis:');
    stdout.writeln('  • Levenshtein distance against popular Dart/Flutter packages');
    stdout.writeln('  • Suspicious prefix/suffix patterns (flutter_, dart_, etc.)');
    stdout.writeln('  • Dependency confusion — local names that exist on pub.dev');
    stdout.writeln();
    stdout.writeln(parser.usage);
    exit(0);
  }

  final pubspecPath = opts['pubspec'] as String;
  final format = opts['format'] as String;

  // Parse pubspec.yaml.
  final pubspecFile = File(pubspecPath);
  if (!pubspecFile.existsSync()) {
    stderr.writeln('Error: $pubspecPath not found.');
    exit(1);
  }

  final pubspec = loadYaml(pubspecFile.readAsStringSync()) as YamlMap;
  final deps = pubspec['dependencies'] as YamlMap?;
  final devDeps = pubspec['dev_dependencies'] as YamlMap?;

  final allNames = <String>[
    if (deps != null) ...deps.keys.cast<String>(),
    if (devDeps != null) ...devDeps.keys.cast<String>(),
  ];

  if (allNames.isEmpty) {
    stdout.writeln('No dependencies found in $pubspecPath.');
    exit(0);
  }

  if (format == 'text') {
    stdout.writeln('Analyzing ${allNames.length} dependencies for typosquatting and confusion...');
  }

  // Run typosquat analysis.
  final detector = TyposquatDetector();
  final typosquatFindings = detector.analyze(allNames);

  // Run confusion analysis (async, checks pub.dev).
  final confusion = ConfusionDetector();
  final confusionFindings = await confusion.analyze(allNames);

  if (format == 'json') {
    stdout.writeln(const JsonEncoder.withIndent('  ').convert({
      'packages': allNames,
      'typosquatFindings': typosquatFindings.map((f) => f.toJson()).toList(),
      'confusionFindings': confusionFindings.map((f) => f.toJson()).toList(),
    }));
  } else {
    stdout.writeln();
    stdout.writeln('dart_audit — Typosquat & Confusion Analysis');
    stdout.writeln('─' * 60);

    final hasFindings = typosquatFindings.isNotEmpty || confusionFindings.isNotEmpty;
    if (!hasFindings) {
      stdout.writeln('  ✔ No typosquatting or confusion indicators found.');
    } else {
      if (typosquatFindings.isNotEmpty) {
        stdout.writeln();
        stdout.writeln('  Typosquatting:');
        for (final f in typosquatFindings) {
          final label = switch (f.severity) {
            'CRITICAL' => '\x1B[31m[CRITICAL]\x1B[0m',
            'HIGH' => '\x1B[31m[HIGH]    \x1B[0m',
            'MEDIUM' => '\x1B[33m[MEDIUM]  \x1B[0m',
            _ => '\x1B[2m[LOW]     \x1B[0m',
          };
          stdout.writeln('    $label ${f.description}');
          if (f.matchedPublicPackage != null) {
            stdout.writeln('      Similar to: ${f.matchedPublicPackage}');
          }
        }
      }
      if (confusionFindings.isNotEmpty) {
        stdout.writeln();
        stdout.writeln('  Dependency Confusion:');
        for (final f in confusionFindings) {
          final label = switch (f.severity) {
            'CRITICAL' => '\x1B[31m[CRITICAL]\x1B[0m',
            'HIGH' => '\x1B[31m[HIGH]    \x1B[0m',
            'MEDIUM' => '\x1B[33m[MEDIUM]  \x1B[0m',
            _ => '\x1B[2m[LOW]     \x1B[0m',
          };
          stdout.writeln('    $label ${f.description}');
        }
      }
    }

    stdout.writeln('─' * 60);
    stdout.writeln();
  }

  final hasCritical = typosquatFindings.any((f) => f.severity == 'CRITICAL' || f.severity == 'HIGH') ||
      confusionFindings.any((f) => f.severity == 'CRITICAL' || f.severity == 'HIGH');
  exit(hasCritical ? 1 : 0);
}

// ── Help ───────────────────────────────────────────────────────────────────────

void _printTopLevelHelp(String version, ArgParser parser) {
  stdout.writeln('dart_audit $version — Dart/Flutter supply-chain security tool');
  stdout.writeln();
  stdout.writeln('Commands:');
  stdout.writeln('  audit       Scan pubspec.lock against OSV.dev for known CVEs (default)');
  stdout.writeln('  inspect     Deep security analysis of a pub.dev package');
  stdout.writeln('  trust       Assess package trust metadata from pub.dev');
  stdout.writeln('  typosquat   Detect typosquatting and dependency confusion in dependencies');
  stdout.writeln();
  stdout.writeln('Global options:');
  stdout.writeln(parser.usage);
  stdout.writeln();
  stdout.writeln('Run `dart_audit <command> --help` for command-specific options.');
  stdout.writeln();
  stdout.writeln('Examples:');
  stdout.writeln('  dart_audit audit                         # scan current project');
  stdout.writeln('  dart_audit inspect http 1.2.0            # deep inspect a package');
  stdout.writeln('  dart_audit trust http                    # check package trust');
  stdout.writeln('  dart_audit typosquat                     # check for typosquats');
}
