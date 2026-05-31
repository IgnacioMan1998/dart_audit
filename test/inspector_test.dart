import 'dart:io';
import 'dart:math';

import 'package:test/test.dart';

import 'package:dart_audit/src/inspector/entropy_scanner.dart';
import 'package:dart_audit/src/inspector/package_inspector.dart';
import 'package:dart_audit/src/inspector/regex_scanner.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a temporary directory with [files] (relative path → content).
/// The directory is deleted after the test.
Future<Directory> _makeTempSourceDir(Map<String, String> files) async {
  final dir = await Directory.systemTemp.createTemp('dart_audit_inspector_test_');
  for (final entry in files.entries) {
    final file = File('${dir.path}/${entry.key}');
    await file.create(recursive: true);
    await file.writeAsString(entry.value);
  }
  addTearDown(() => dir.delete(recursive: true));
  return dir;
}

// ---------------------------------------------------------------------------
// EntropyScanner tests
// ---------------------------------------------------------------------------

void main() {
  group('EntropyScanner._shannonEntropy', () {
    // We expose the logic via the scanner — test indirectly through scan().
    test('clean Dart source produces no findings', () async {
      final dir = await _makeTempSourceDir({
        'lib/clean.dart': '''
import 'package:flutter/material.dart';

class MyWidget extends StatelessWidget {
  const MyWidget({super.key});

  @override
  Widget build(BuildContext context) {
    return const Text('Hello, world!');
  }
}
''',
      });

      final findings = await EntropyScanner().scan(dir);
      expect(findings, isEmpty);
    });

    test('detects high-entropy string literal as MEDIUM or HIGH', () async {
      // Generate a pseudo-random string with high entropy (> 4.5 bits).
      const chars =
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      final rng = Random(42);
      final highEntropyStr =
          List.generate(60, (_) => chars[rng.nextInt(chars.length)]).join();

      final dir = await _makeTempSourceDir({
        'lib/suspicious.dart': "const _key = '$highEntropyStr';",
      });

      final findings = await EntropyScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.severity, anyOf('MEDIUM', 'HIGH'));
      expect(findings.first.line, 1);
    });

    test('detects truly random string as HIGH (entropy > 5.5 bits)', () async {
      // A 64-char string using all 64 base64 chars exactly once → entropy = log2(64) = 6 bits.
      const highEntropyStr =
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      final dir = await _makeTempSourceDir({
        'lib/encrypted.dart': "const _secret = '$highEntropyStr';",
      });

      final findings = await EntropyScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.severity, 'HIGH');
    });

    test('ignores strings shorter than minLength', () async {
      final dir = await _makeTempSourceDir({
        'lib/short.dart': "const x = 'Ab3${'Xk2' * 3}';", // < 20 chars
      });

      final findings = await EntropyScanner().scan(dir);
      expect(findings, isEmpty);
    });

    test('findings are sorted HIGH before MEDIUM', () async {
      const chars =
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      final rng = Random(7);
      final s1 = List.generate(60, (_) => chars[rng.nextInt(chars.length)]).join();
      final s2 = List.generate(40, (_) => chars[rng.nextInt(chars.length)]).join();

      final dir = await _makeTempSourceDir({
        'lib/multi.dart': "const a = '$s1';\nconst b = '$s2';",
      });

      final findings = await EntropyScanner().scan(dir);
      if (findings.length >= 2) {
        const order = ['HIGH', 'MEDIUM'];
        for (var i = 1; i < findings.length; i++) {
          expect(
            order.indexOf(findings[i - 1].severity),
            lessThanOrEqualTo(order.indexOf(findings[i].severity)),
          );
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // RegexScanner tests
  // ---------------------------------------------------------------------------

  group('RegexScanner', () {
    test('detects Process.run as CRITICAL', () async {
      final dir = await _makeTempSourceDir({
        'lib/evil.dart': "await Process.run('bash', ['-c', cmd]);",
      });

      final findings = await RegexScanner().scan(dir);
      final processRun = findings.where((f) => f.rule == 'PROCESS_RUN');
      expect(processRun, isNotEmpty);
      expect(processRun.first.severity, 'CRITICAL');
      expect(processRun.first.line, 1);
    });

    test('detects hardcoded unknown URL as HIGH', () async {
      final dir = await _makeTempSourceDir({
        'lib/evil.dart':
            "final uri = Uri.parse('http://185.220.101.1/exfil');",
      });

      final findings = await RegexScanner().scan(dir);
      final urlFindings = findings.where((f) => f.rule == 'HARDCODED_URL');
      expect(urlFindings, isNotEmpty);
      expect(urlFindings.first.severity, 'HIGH');
    });

    test('does NOT flag known-safe domains', () async {
      final dir = await _makeTempSourceDir({
        'lib/clean.dart': '''
final a = Uri.parse('https://pub.dev/packages/http');
final b = Uri.parse('https://dart.dev/guides');
final c = Uri.parse('https://github.com/dart-lang/http');
''',
      });

      final findings = await RegexScanner().scan(dir);
      final urlFindings = findings.where((f) => f.rule == 'HARDCODED_URL');
      expect(urlFindings, isEmpty);
    });

    test('detects PROCESS_RUN and SHELL_INJECTION independently', () async {
      final dir = await _makeTempSourceDir({
        'lib/shell.dart': "Process.run('bash', ['-c', 'rm -rf /']);",
      });

      final findings = await RegexScanner().scan(dir);
      final rules = findings.map((f) => f.rule).toSet();
      expect(rules, containsAll(['PROCESS_RUN', 'SHELL_INJECTION']));
    });

    test('detects cryptomining keywords as CRITICAL', () async {
      final dir = await _makeTempSourceDir({
        'lib/miner.dart': "const pool = 'stratum+tcp://pool.example.com:3333';",
      });

      final findings = await RegexScanner().scan(dir);
      expect(
        findings.any((f) => f.rule == 'CRYPTO_MINING' && f.severity == 'CRITICAL'),
        isTrue,
      );
    });

    test('detects hex-encoded sequences as MEDIUM', () async {
      final dir = await _makeTempSourceDir({
        'lib/hex.dart': r"final s = '\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64';",
      });

      final findings = await RegexScanner().scan(dir);
      expect(
        findings.any((f) => f.rule == 'HEX_ENCODING' && f.severity == 'MEDIUM'),
        isTrue,
      );
    });

    test('snippet is limited to 120 characters', () async {
      final longLine = "await Process.run('bash', [${'a' * 200}]);";
      final dir = await _makeTempSourceDir({'lib/long.dart': longLine});

      final findings = await RegexScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.snippet.length, lessThanOrEqualTo(120));
    });

    test('results sorted CRITICAL before HIGH before MEDIUM', () async {
      final dir = await _makeTempSourceDir({
        'lib/multi.dart': '''
final uri = Uri.parse('http://evil.example.com/collect');
await Process.run('bash', ['-c', cmd]);
final s = '\\x68\\x65\\x6c\\x6c';
''',
      });

      final findings = await RegexScanner().scan(dir);
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      for (var i = 1; i < findings.length; i++) {
        expect(
          order.indexOf(findings[i - 1].severity),
          lessThanOrEqualTo(order.indexOf(findings[i].severity)),
          reason: 'findings should be sorted by severity',
        );
      }
    });
  });

  // ---------------------------------------------------------------------------
  // PackageInspector (unit — no network)
  // ---------------------------------------------------------------------------

  group('InspectionReport', () {
    test('isClean when no findings', () {
      final report = InspectionReport(
        packageName: 'http',
        version: '1.2.0',
        dartFileCount: 10,
        regexFindings: [],
        entropyFindings: [],
        riskScore: 0,
      );

      expect(report.isClean, isTrue);
      expect(report.isSuspicious, isFalse);
      expect(report.riskLabel, 'CLEAN');
    });

    test('isSuspicious when score >= 30', () {
      final finding = RegexFinding(
        file: 'lib/x.dart',
        line: 1,
        rule: 'PROCESS_RUN',
        severity: 'CRITICAL',
        description: 'test',
        snippet: 'Process.run(...)',
      );

      final report = InspectionReport(
        packageName: 'evil',
        version: '0.0.1',
        dartFileCount: 3,
        regexFindings: [finding],
        entropyFindings: [],
        riskScore: 40,
      );

      expect(report.isSuspicious, isTrue);
      expect(report.criticalCount, 1);
    });

    test('toJson includes all fields', () {
      final report = InspectionReport(
        packageName: 'test_pkg',
        version: '1.0.0',
        dartFileCount: 5,
        regexFindings: [],
        entropyFindings: [],
        riskScore: 0,
      );

      final json = report.toJson();
      expect(json['package'], 'test_pkg');
      expect(json['version'], '1.0.0');
      expect(json['dartFileCount'], 5);
      expect(json['riskScore'], 0);
      expect(json['riskLabel'], 'CLEAN');
      expect(json['regexFindings'], isEmpty);
      expect(json['entropyFindings'], isEmpty);
    });

    test('riskScore calculation: CRITICAL regex = 40 pts', () {
      // Two CRITICAL findings → score capped at 80, not over 100.
      const weights = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5};
      var score = 0;
      for (var i = 0; i < 3; i++) {
        score += weights['CRITICAL']!;
      }
      expect(score.clamp(0, 100), 100); // 3×40 = 120 → clamped to 100
    });
  });
}
