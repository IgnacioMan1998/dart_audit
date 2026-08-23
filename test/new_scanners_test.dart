import 'dart:io';

import 'package:test/test.dart';
import 'package:yaml/yaml.dart';
import 'package:archive/archive.dart';

import 'package:dart_audit/src/inspector/unicode_scanner.dart';
import 'package:dart_audit/src/inspector/archive_scanner.dart';
import 'package:dart_audit/src/inspector/typosquat_detector.dart';
import 'package:dart_audit/src/inspector/pubspec_scanner.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Future<Directory> _makeTempDir(Map<String, String> files) async {
  final dir = await Directory.systemTemp.createTemp('dart_audit_new_tests_');
  for (final entry in files.entries) {
    final file = File('${dir.path}/${entry.key}');
    await file.create(recursive: true);
    await file.writeAsString(entry.value);
  }
  addTearDown(() => dir.delete(recursive: true));
  return dir;
}

// ---------------------------------------------------------------------------
// UnicodeScanner tests
// ---------------------------------------------------------------------------

void main() {
  group('UnicodeScanner', () {
    test('detects RIGHT-TO-LEFT OVERRIDE (U+202E) as CRITICAL', () async {
      final dir = await _makeTempDir({
        'lib/evil.dart': "final x = 'hello'; // \u202E comment",
      });

      final findings = await UnicodeScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'BIDI_OVERRIDE');
      expect(findings.first.severity, 'CRITICAL');
      expect(findings.first.codepoint, 'U+202E');
    });

    test('detects LEFT-TO-RIGHT EMBEDDING (U+202A) as CRITICAL', () async {
      final dir = await _makeTempDir({
        'lib/evil.dart': "const s = '\u202Ahidden\u202C';",
      });

      final findings = await UnicodeScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'BIDI_OVERRIDE');
      expect(findings.first.severity, 'CRITICAL');
    });

    test('detects zero-width space (U+200B) as HIGH', () async {
      final dir = await _makeTempDir({
        'lib/stealth.dart': "const name = 'clean\u200Bcode';",
      });

      final findings = await UnicodeScanner().scan(dir);
      final zwfFindings = findings.where((f) => f.rule == 'ZERO_WIDTH');
      expect(zwfFindings, isNotEmpty);
      expect(zwfFindings.first.severity, 'HIGH');
    });

    test('detects variation selector (U+FE0F) as CRITICAL (GlassWorm)', () async {
      final dir = await _makeTempDir({
        'lib/glassworm.dart': "const payload = 'data\uFE0Fhidden';",
      });

      final findings = await UnicodeScanner().scan(dir);
      final puaFindings = findings.where((f) => f.rule == 'PUA_CARRIER');
      expect(puaFindings, isNotEmpty);
      expect(puaFindings.first.severity, 'CRITICAL');
      expect(puaFindings.first.description, contains('GlassWorm'));
    });

    test('detects Cyrillic homoglyph in identifier as HIGH', () async {
      // Cyrillic 'а' (U+0430) looks like Latin 'a'
      final dir = await _makeTempDir({
        'lib/homoglyph.dart': "const user\u0430me = 'admin';",
      });

      final findings = await UnicodeScanner().scan(dir);
      final homoglyphFindings = findings.where((f) => f.rule == 'HOMOGLYPH');
      expect(homoglyphFindings, isNotEmpty);
      expect(homoglyphFindings.first.severity, 'HIGH');
      expect(homoglyphFindings.first.description, contains('Cyrillic'));
    });

    test('clean Dart source produces no findings', () async {
      final dir = await _makeTempDir({
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

      final findings = await UnicodeScanner().scan(dir);
      expect(findings, isEmpty);
    });

    test('findings are sorted CRITICAL before HIGH', () async {
      final dir = await _makeTempDir({
        'lib/multi.dart': "const a = '\u202Ereverse\u202C';\nconst b = 'clean\u200B';",
      });

      final findings = await UnicodeScanner().scan(dir);
      if (findings.length >= 2) {
        const order = ['CRITICAL', 'HIGH'];
        for (var i = 1; i < findings.length; i++) {
          expect(
            order.indexOf(findings[i - 1].severity),
            lessThanOrEqualTo(order.indexOf(findings[i].severity)),
          );
        }
      }
    });

    test('snippet shows context around suspicious character', () async {
      final dir = await _makeTempDir({
        'lib/context.dart': "final url = 'https://example.com/\u202Epath';",
      });

      final findings = await UnicodeScanner().scan(dir);
      expect(findings, isNotEmpty);
      expect(findings.first.snippet, contains('◄HERE►'));
    });
  });

  // ---------------------------------------------------------------------------
  // ArchiveScanner tests
  // ---------------------------------------------------------------------------

  group('ArchiveScanner', () {
    test('detects path traversal entries', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('lib/evil.dart', 10, [0, 1, 2, 3]));
      archive.addFile(ArchiveFile('../etc/passwd', 10, [0, 1, 2, 3]));

      final result = ArchiveScanner().scan(archive);
      expect(result.isClean, isFalse);
      expect(
        result.findings.any((f) => f.rule == 'PARENT_TRAVERSAL'),
        isTrue,
      );
    });

    test('detects absolute path entries', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('/etc/passwd', 10, [0, 1, 2, 3]));

      final result = ArchiveScanner().scan(archive);
      expect(result.isClean, isFalse);
      expect(
        result.findings.any((f) => f.rule == 'ABSOLUTE_PATH'),
        isTrue,
      );
    });

    test('detects parent traversal in path segments', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('a/../b/file.dart', 10, [0, 1, 2, 3]));

      final result = ArchiveScanner().scan(archive);
      expect(result.isClean, isFalse);
      // This entry has '..' in the segments but also normalizes to b/file.dart
      // The PARENT_TRAVERSAL rule fires on any entry with '..' segment
      expect(
        result.findings.any((f) => f.rule == 'PARENT_TRAVERSAL' || f.rule == 'PATH_TRAVERSAL'),
        isTrue,
      );
    });

    test('counts dart files correctly', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('lib/a.dart', 10, [0, 1]));
      archive.addFile(ArchiveFile('lib/b.dart', 10, [0, 1]));
      archive.addFile(ArchiveFile('lib/c.txt', 10, [0, 1]));

      final result = ArchiveScanner().scan(archive);
      expect(result.dartFileCount, 2);
      expect(result.fileCount, 3);
    });

    test('clean archive produces no findings', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('lib/a.dart', 10, [0, 1, 2, 3]));
      archive.addFile(ArchiveFile('lib/b.dart', 10, [0, 1, 2, 3]));

      final result = ArchiveScanner().scan(archive);
      expect(result.isClean, isTrue);
    });

    test('findings are sorted CRITICAL first', () {
      final archive = Archive();
      archive.addFile(ArchiveFile('../etc/passwd', 10, [0, 1]));
      archive.addFile(ArchiveFile('lib/.hidden.dart', 10, [0, 1]));

      final result = ArchiveScanner().scan(archive);
      if (result.findings.length >= 2) {
        expect(result.findings.first.severity, 'CRITICAL');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // TyposquatDetector tests
  // ---------------------------------------------------------------------------

  group('TyposquatDetector', () {
    test('detects 1-edit typosquat of popular package', () {
      // "htpp" is 1 edit from "http"
      final findings = TyposquatDetector().analyze(['htpp']);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'LEVENSHTEIN_1');
      expect(findings.first.severity, 'CRITICAL');
      expect(findings.first.matchedPublicPackage, 'http');
    });

    test('detects 2-edit typosquat of popular package', () {
      // "proivder" is 2 edits (swap v/i) from "provider"
      final findings = TyposquatDetector().analyze(['proivder']);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'LEVENSHTEIN_2');
      expect(findings.first.severity, 'HIGH');
    });

    test('detects flutter_ prefix confusion', () {
      final findings = TyposquatDetector().analyze(['flutter_http']);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'PREFIX_FLUTTER');
      expect(findings.first.matchedPublicPackage, 'http');
    });

    test('detects dart_ prefix confusion', () {
      final findings = TyposquatDetector().analyze(['dart_http']);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'PREFIX_DART_PUB');
    });

    test('does NOT flag legitimate package names', () {
      final findings = TyposquatDetector().analyze([
        'http',
        'path',
        'provider',
        'my_awesome_widget',
        'company_internal_lib',
      ]);
      expect(findings, isEmpty);
    });

    test('findings include local package name', () {
      final findings = TyposquatDetector().analyze(['htpp']);
      expect(findings.first.localPackage, 'htpp');
    });
  });

  // ---------------------------------------------------------------------------
  // PubspecScanner tests
  // ---------------------------------------------------------------------------

  group('PubspecScanner', () {
    test('detects wildcard version constraint', () {
      final pubspec = loadYaml('''
dependencies:
  evil_pkg: "*"
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'WILDCARD_VERSION');
      expect(findings.first.severity, 'HIGH');
      expect(findings.first.packageName, 'evil_pkg');
    });

    test('detects "any" version constraint', () {
      final pubspec = loadYaml('''
dependencies:
  risky_pkg: any
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'ANY_VERSION');
    });

    test('detects git dependency with branch ref', () {
      final pubspec = loadYaml('''
dependencies:
  my_pkg:
    git:
      url: https://github.com/user/repo.git
      ref: main
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'GIT_BRANCH_REF');
    });

    test('detects git dependency with IP address', () {
      final pubspec = loadYaml('''
dependencies:
  evil_pkg:
    git:
      url: http://192.168.1.1/repo.git
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'GIT_IP_ADDRESS');
      expect(findings.first.severity, 'CRITICAL');
    });

    test('detects path dependency', () {
      final pubspec = loadYaml('''
dependencies:
  local_pkg:
    path: ../local_pkg
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'PATH_DEPENDENCY');
    });

    test('detects dependency override', () {
      final pubspec = loadYaml('''
dependency_overrides:
  http: 1.0.0
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isNotEmpty);
      expect(findings.first.rule, 'DEPENDENCY_OVERRIDE');
    });

    test('clean pubspec produces no findings', () {
      final pubspec = loadYaml('''
dependencies:
  http: ^1.0.0
  path: ^1.0.0

dev_dependencies:
  test: ^1.0.0

environment:
  sdk: ">=3.0.0 <4.0.0"
''') as YamlMap;

      final findings = PubspecScanner().scan(pubspec);
      expect(findings, isEmpty);
    });
  });
}
