import 'dart:io';

import 'package:test/test.dart';
import 'package:dart_audit/dart_audit.dart';


class MockTrustScorer implements TrustScorer {
  MockTrustScorer({this.mockInfo, this.shouldReturnNull = false});

  final PackageTrustInfo? mockInfo;
  final bool shouldReturnNull;

  @override
  Future<PackageTrustInfo?> assess(String packageName) async {
    if (shouldReturnNull) return null;
    return mockInfo ??
        PackageTrustInfo(
          packageName: packageName,
          version: '1.0.0',
          createdAt: DateTime.now().subtract(const Duration(days: 100)),
          publisher: 'example.com',
          isVerifiedPublisher: true,
          findings: [],
        );
  }
}


class MockInspector implements PackageInspector {
  MockInspector({this.riskScore = 0, this.shouldThrow = false});

  final int riskScore;
  final bool shouldThrow;

  @override
  Future<InspectionReport> inspect(
    String packageName,
    String packageVersion, {
    void Function(String status)? onStatus,
  }) async {
    if (shouldThrow) throw StateError('download failed');
    return InspectionReport(
      packageName: packageName,
      version: packageVersion,
      dartFileCount: 5,
      regexFindings: const [],
      entropyFindings: const [],
      riskScore: riskScore,
    );
  }

  @override
  ArchiveScanResult scanArchive(List<int> archiveBytes) {
    return const ArchiveScanResult(
      totalEntries: 0,
      fileCount: 0,
      dartFileCount: 0,
      findings: [],
    );
  }
}

void main() {
  group('GitHookManager', () {
    late Directory tempDir;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('dart_audit_hook_test_');
    });

    tearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });

    test('throws FileSystemException when not in git repository', () {
      final manager = GitHookManager(workingDirectory: tempDir.path);
      expect(() => manager.installHook(), throwsA(isA<FileSystemException>()));
    });

    test('installs and removes pre-commit hook in git repository', () {
      final init = Process.runSync('git', ['init', '--quiet'], workingDirectory: tempDir.path);
      expect(init.exitCode, 0);
      final manager = GitHookManager(workingDirectory: tempDir.path);

      expect(manager.isHookInstalled(), isFalse);

      final installed = manager.installHook();
      expect(installed, isTrue);
      expect(manager.isHookInstalled(), isTrue);

      final hookFile = File('${tempDir.path}/.git/hooks/pre-commit');
      expect(hookFile.existsSync(), isTrue);
      expect(hookFile.readAsStringSync(), contains('Installed by dart_audit'));

      final removed = manager.removeHook();
      expect(removed, isTrue);
      expect(manager.isHookInstalled(), isFalse);
      expect(hookFile.existsSync(), isFalse);
    });

    test('does not overwrite or remove a hook it does not own', () {
      final init = Process.runSync('git', ['init', '--quiet'], workingDirectory: tempDir.path);
      expect(init.exitCode, 0);
      final hookFile = File('${tempDir.path}/.git/hooks/pre-commit')
        ..createSync(recursive: true)
        ..writeAsStringSync('#!/bin/sh\necho existing hook\n');
      final manager = GitHookManager(workingDirectory: tempDir.path);

      expect(() => manager.installHook(), throwsA(isA<FileSystemException>()));
      expect(manager.removeHook(), isFalse);
      expect(hookFile.readAsStringSync(), contains('existing hook'));
    });
  });

  group('SafePackageAdder', () {
    test('returns error when package is not found on pub.dev', () async {
      final adder = SafePackageAdder(
        trustScorer: MockTrustScorer(shouldReturnNull: true),
        inspector: MockInspector(),
        typosquatDetector: TyposquatDetector(),
      );


      final result = await adder.addPackage(
        packageName: 'non_existent_pkg_12345',
      );

      expect(result.isClean, isFalse);
      expect(result.installed, isFalse);
      expect(result.errorMessage, contains('was not found on pub.dev'));
    });

    test('flags typosquatting package and prevents installation', () async {
      final adder = SafePackageAdder(
        trustScorer: MockTrustScorer(),
        inspector: MockInspector(),
        typosquatDetector: TyposquatDetector(),
      );

      // 'fluter_hooks' is a 1-edit typosquat of 'flutter_hooks'
      final result = await adder.addPackage(
        packageName: 'fluter_hooks',
      );

      expect(result.isClean, isFalse);
      expect(result.installed, isFalse);
      expect(result.typosquatFindings, isNotEmpty);
      expect(result.errorMessage, contains('Security audit flagged potential risks'));
    });

    test('fails closed when source inspection cannot complete', () async {
      final adder = SafePackageAdder(
        trustScorer: MockTrustScorer(),
        inspector: MockInspector(shouldThrow: true),
        typosquatDetector: TyposquatDetector(),
      );

      final result = await adder.addPackage(packageName: 'example_package', force: true);

      expect(result.isClean, isFalse);
      expect(result.installed, isFalse);
      expect(result.errorMessage, contains('Could not complete source inspection'));
    });

    test('rejects version constraints because they cannot be inspected exactly', () async {
      final adder = SafePackageAdder(
        trustScorer: MockTrustScorer(),
        inspector: MockInspector(),
        typosquatDetector: TyposquatDetector(),
      );

      final result = await adder.addPackage(
        packageName: 'example_package',
        versionConstraint: '^1.0.0',
      );

      expect(result.isClean, isFalse);
      expect(result.installed, isFalse);
      expect(result.errorMessage, contains('Version constraints are not supported'));
    });
  });
}
