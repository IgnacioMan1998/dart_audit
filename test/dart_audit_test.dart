import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'package:dart_audit/src/lockfile_parser.dart';
import 'package:dart_audit/src/osv_client.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Writes [content] to a temp file and returns the path.
String _writeTempFile(String content) {
  final file = File('${Directory.systemTemp.path}/dart_audit_test_${DateTime.now().microsecondsSinceEpoch}.lock');
  file.writeAsStringSync(content);
  addTearDown(file.deleteSync);
  return file.path;
}

/// Minimal valid pubspec.lock with one hosted and one git package.
const _sampleLockfile = '''
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dartlang.org"
    source: hosted
    version: "0.13.6"
  my_git_pkg:
    dependency: "direct main"
    description:
      url: "https://github.com/example/my_git_pkg.git"
      ref: main
      resolved-ref: abc123
      path: "."
    source: git
    version: "1.0.0"
  some_transitive:
    dependency: "transitive"
    description:
      name: some_transitive
      url: "https://pub.dartlang.org"
    source: hosted
    version: "2.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
''';

/// A fake OSV batch response with one vulnerability for 'http' and none for the rest.
Map<String, dynamic> _osvResponseWith({required String packageName}) => {
      'results': [
        {
          'vulns': [
            {
              'id': 'GHSA-test-1234-5678',
              'summary': 'A test vulnerability in $packageName',
              'aliases': ['CVE-2024-00001'],
              'severity': [
                {'type': 'CVSS_V3', 'score': '7.5'},
              ],
              'affected': [
                {
                  'package': {'name': packageName, 'ecosystem': 'Pub'},
                  'ranges': [
                    {
                      'type': 'ECOSYSTEM',
                      'events': [
                        {'introduced': '0.0.0'},
                        {'fixed': '1.0.0'},
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
        {'vulns': []},
      ],
    };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // ── lockfile_parser ────────────────────────────────────────────────────────
  group('parseLockfile', () {
    test('returns hosted packages and skipped packages separately', () {
      final path = _writeTempFile(_sampleLockfile);
      final result = parseLockfile(path);

      expect(result.hostedPackages, hasLength(2));
      expect(result.skippedPackages, hasLength(1));
      expect(result.skippedPackages.first.name, 'my_git_pkg');
      expect(result.skippedPackages.first.source, 'git');
    });

    test('marks direct vs transitive correctly', () {
      final path = _writeTempFile(_sampleLockfile);
      final result = parseLockfile(path);

      final httpPkg = result.hostedPackages.firstWhere((p) => p.name == 'http');
      final transitive =
          result.hostedPackages.firstWhere((p) => p.name == 'some_transitive');

      expect(httpPkg.isDirect, isTrue);
      expect(transitive.isDirect, isFalse);
    });

    test('orders direct packages before transitive', () {
      final path = _writeTempFile(_sampleLockfile);
      final result = parseLockfile(path);

      expect(result.hostedPackages.first.isDirect, isTrue);
      expect(result.hostedPackages.last.isDirect, isFalse);
    });

    test('throws FileSystemException for missing file', () {
      expect(
        () => parseLockfile('/nonexistent/path/pubspec.lock'),
        throwsA(isA<FileSystemException>()),
      );
    });

    test('returns empty lists when packages key is absent', () {
      final path = _writeTempFile('sdks:\n  dart: ">=3.0.0 <4.0.0"\n');
      final result = parseLockfile(path);
      expect(result.hostedPackages, isEmpty);
      expect(result.skippedPackages, isEmpty);
    });
  });

  // ── OsvSeverity helpers ────────────────────────────────────────────────────
  group('OsvSeverity', () {
    test('fromString maps known values case-insensitively', () {
      expect(OsvSeverity.fromString('CRITICAL'), OsvSeverity.critical);
      expect(OsvSeverity.fromString('high'), OsvSeverity.high);
      expect(OsvSeverity.fromString('Moderate'), OsvSeverity.medium);
      expect(OsvSeverity.fromString('LOW'), OsvSeverity.low);
      expect(OsvSeverity.fromString('garbage'), OsvSeverity.unknown);
    });

    test('priority is ordered most-severe first', () {
      expect(OsvSeverity.critical.priority, lessThan(OsvSeverity.high.priority));
      expect(OsvSeverity.high.priority, lessThan(OsvSeverity.medium.priority));
      expect(OsvSeverity.medium.priority, lessThan(OsvSeverity.low.priority));
      expect(OsvSeverity.low.priority, lessThan(OsvSeverity.unknown.priority));
    });
  });

  // ── queryOsv ──────────────────────────────────────────────────────────────
  group('queryOsv', () {
    test('returns vulnerability when OSV reports one', () async {
      final fakeClient = MockClient((request) async {
        return http.Response(
          jsonEncode(_osvResponseWith(packageName: 'http')),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final packages = [
        const LockedPackage(name: 'http', version: '0.13.6', source: 'hosted', isDirect: true),
        const LockedPackage(name: 'yaml', version: '3.1.2', source: 'hosted', isDirect: false),
      ];

      final results = await queryOsv(packages, client: fakeClient);

      expect(results, hasLength(2));
      expect(results[0].isVulnerable, isTrue);
      expect(results[0].vulnerabilities.first.id, 'GHSA-test-1234-5678');
      expect(results[0].vulnerabilities.first.fixedVersion, '1.0.0');
      expect(results[0].vulnerabilities.first.severity, OsvSeverity.high);
      expect(results[0].vulnerabilities.first.aliases, contains('CVE-2024-00001'));
      expect(results[1].isVulnerable, isFalse);
    });

    test('throws after retries on network error', () async {
      var calls = 0;
      final fakeClient = MockClient((_) async {
        calls++;
        throw const SocketException('connection refused');
      });

      final packages = [
        const LockedPackage(name: 'http', version: '0.13.6', source: 'hosted', isDirect: true),
      ];

      await expectLater(
        queryOsv(packages, client: fakeClient),
        throwsA(isA<http.ClientException>()),
      );
      expect(calls, 3); // _maxRetries
    });

    test('calls onBatchProgress callback', () async {
      final fakeClient = MockClient((request) async {
        final body = jsonDecode(request.body) as Map<String, dynamic>;
        final queries = body['queries'] as List;
        return http.Response(
          jsonEncode({'results': List.generate(queries.length, (_) => {'vulns': []})}),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final packages = List.generate(
        5,
        (i) => LockedPackage(name: 'pkg$i', version: '1.0.0', source: 'hosted', isDirect: false),
      );

      int? lastDone;
      int? lastTotal;

      await queryOsv(
        packages,
        client: fakeClient,
        onBatchProgress: (done, total) {
          lastDone = done;
          lastTotal = total;
        },
      );

      expect(lastDone, 5);
      expect(lastTotal, 5);
    });

    test('toJson serializes vulnerability correctly', () {
      const vuln = OsvVulnerability(
        id: 'GHSA-xxxx',
        summary: 'Test',
        severity: OsvSeverity.critical,
        fixedVersion: '2.0.0',
        aliases: ['CVE-2024-0001'],
        detailsUrl: 'https://osv.dev/vulnerability/GHSA-xxxx',
      );

      final json = vuln.toJson();
      expect(json['id'], 'GHSA-xxxx');
      expect(json['severity'], 'critical');
      expect(json['fixedVersion'], '2.0.0');
      expect(json['aliases'], contains('CVE-2024-0001'));
    });
  });
}

