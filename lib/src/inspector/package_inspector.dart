import 'dart:io';

import 'package:archive/archive.dart';
import 'package:http/http.dart' as http;

import 'package_downloader.dart';
import 'regex_scanner.dart';
import 'entropy_scanner.dart';
import 'unicode_scanner.dart';
import 'archive_scanner.dart';
import 'trust_scorer.dart';

// Risk score weights by severity — all scanner types.
const _regexWeights = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5};
const _entropyWeights = {'HIGH': 15, 'MEDIUM': 5};
const _unicodeWeights = {'CRITICAL': 35, 'HIGH': 15};
const _archiveWeights = {'CRITICAL': 30, 'HIGH': 10};
const _trustWeights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 3};

/// Full source-inspection result for a single package version.
class InspectionReport {
  const InspectionReport({
    required this.packageName,
    required this.version,
    required this.dartFileCount,
    required this.regexFindings,
    required this.entropyFindings,
    this.unicodeFindings = const [],
    this.archiveFindings = const [],
    this.trustInfo,
    required this.riskScore,
  });

  final String packageName;
  final String version;

  /// Number of `.dart` files analyzed.
  final int dartFileCount;

  final List<RegexFinding> regexFindings;
  final List<EntropyFinding> entropyFindings;
  final List<UnicodeFinding> unicodeFindings;
  final List<ArchiveFinding> archiveFindings;
  final PackageTrustInfo? trustInfo;

  /// Composite risk score from 0 (clean) to 100 (highly suspicious).
  final int riskScore;

  int get criticalCount =>
      regexFindings.where((f) => f.severity == 'CRITICAL').length +
      unicodeFindings.where((f) => f.severity == 'CRITICAL').length +
      archiveFindings.where((f) => f.severity == 'CRITICAL').length +
      (trustInfo?.findings.where((f) => f.severity == 'CRITICAL').length ?? 0);

  int get highCount =>
      regexFindings.where((f) => f.severity == 'HIGH').length +
      entropyFindings.where((f) => f.severity == 'HIGH').length +
      unicodeFindings.where((f) => f.severity == 'HIGH').length +
      archiveFindings.where((f) => f.severity == 'HIGH').length +
      (trustInfo?.findings.where((f) => f.severity == 'HIGH').length ?? 0);

  int get mediumCount =>
      regexFindings.where((f) => f.severity == 'MEDIUM').length +
      entropyFindings.where((f) => f.severity == 'MEDIUM').length +
      (trustInfo?.findings.where((f) => f.severity == 'MEDIUM').length ?? 0);

  /// `true` if the risk score reaches the suspicious threshold (≥30).
  bool get isSuspicious => riskScore >= 30;

  /// `true` if no findings were produced.
  bool get isClean =>
      regexFindings.isEmpty &&
      entropyFindings.isEmpty &&
      unicodeFindings.isEmpty &&
      archiveFindings.isEmpty;

  /// Risk label for display.
  String get riskLabel {
    if (riskScore == 0) return 'CLEAN';
    if (riskScore < 30) return 'LOW RISK';
    if (riskScore < 60) return 'SUSPICIOUS';
    return 'HIGH RISK';
  }

  Map<String, dynamic> toJson() => {
        'package': packageName,
        'version': version,
        'dartFileCount': dartFileCount,
        'riskScore': riskScore,
        'riskLabel': riskLabel,
        'regexFindings': regexFindings.map((f) => f.toJson()).toList(),
        'entropyFindings': entropyFindings.map((f) => f.toJson()).toList(),
        'unicodeFindings': unicodeFindings.map((f) => f.toJson()).toList(),
        'archiveFindings': archiveFindings.map((f) => f.toJson()).toList(),
        if (trustInfo != null) 'trustInfo': trustInfo!.toJson(),
      };
}

/// Orchestrates download and parallel scanning of a pub.dev package.
class PackageInspector {
  PackageInspector({
    PackageDownloader? downloader,
    RegexScanner? regexScanner,
    EntropyScanner? entropyScanner,
    UnicodeScanner? unicodeScanner,
    ArchiveScanner? archiveScanner,
    TrustScorer? trustScorer,
    http.Client? client,
  })  : _downloader = downloader ?? PackageDownloader(client: client),
        _regexScanner = regexScanner ?? RegexScanner(),
        _entropyScanner = entropyScanner ?? EntropyScanner(),
        _unicodeScanner = unicodeScanner ?? UnicodeScanner(),
        _archiveScanner = archiveScanner ?? ArchiveScanner(),
        _trustScorer = trustScorer ?? TrustScorer(client: client);

  final PackageDownloader _downloader;
  final RegexScanner _regexScanner;
  final EntropyScanner _entropyScanner;
  final UnicodeScanner _unicodeScanner;
  final ArchiveScanner _archiveScanner;
  final TrustScorer _trustScorer;

  /// Downloads [packageName] at [version], runs all scanners in parallel,
  /// and returns a full [InspectionReport].
  ///
  /// An optional [onStatus] callback receives progress messages.
  Future<InspectionReport> inspect(
    String packageName,
    String version, {
    void Function(String status)? onStatus,
  }) async {
    // 1. Fetch trust metadata (parallel with download).
    final trustFuture = _trustScorer.assess(packageName);

    // 2. Download and extract source.
    final sourceDir = await _downloader.download(
      packageName,
      version,
      onStatus: onStatus,
    );

    final trustInfo = await trustFuture;

    try {
      onStatus?.call('Running security scanners...');

      // Count Dart files before scanning.
      final dartFiles = await sourceDir
          .list(recursive: true)
          .where((e) => e is File && e.path.endsWith('.dart'))
          .length;

      // Run all source scanners in parallel.
      final results = await Future.wait([
        _regexScanner.scan(sourceDir),
        _entropyScanner.scan(sourceDir),
        _unicodeScanner.scan(sourceDir),
      ]);

      final regexFindings = results[0] as List<RegexFinding>;
      final entropyFindings = results[1] as List<EntropyFinding>;
      final unicodeFindings = results[2] as List<UnicodeFinding>;

      // Trust findings are already in trustInfo.

      return InspectionReport(
        packageName: packageName,
        version: version,
        dartFileCount: dartFiles,
        regexFindings: regexFindings,
        entropyFindings: entropyFindings,
        unicodeFindings: unicodeFindings,
        archiveFindings: const [], // Populated externally if archive is scanned.
        trustInfo: trustInfo,
        riskScore: _calculateRiskScore(
          regexFindings,
          entropyFindings,
          unicodeFindings,
          const [],
          trustInfo,
        ),
      );
    } finally {
      // Always clean up the temp directory.
      await sourceDir.delete(recursive: true);
    }
  }

  /// Scans a pre-downloaded tar.gz archive for structural security issues.
  /// This is separate from the source scan since it operates on the raw archive.
  ArchiveScanResult scanArchive(List<int> archiveBytes) {
    final archive = GZipDecoder().decodeBytes(archiveBytes);
    final tarArchive = TarDecoder().decodeBytes(archive);
    return _archiveScanner.scan(tarArchive);
  }

  static int _calculateRiskScore(
    List<RegexFinding> regex,
    List<EntropyFinding> entropy,
    List<UnicodeFinding> unicode,
    List<ArchiveFinding> archive,
    PackageTrustInfo? trust,
  ) {
    var score = 0;

    for (final f in regex) {
      score += _regexWeights[f.severity] ?? 5;
    }
    for (final f in entropy) {
      score += _entropyWeights[f.severity] ?? 0;
    }
    for (final f in unicode) {
      score += _unicodeWeights[f.severity] ?? 0;
    }
    for (final f in archive) {
      score += _archiveWeights[f.severity] ?? 0;
    }
    if (trust != null) {
      for (final f in trust.findings) {
        score += _trustWeights[f.severity] ?? 0;
      }
    }

    return score.clamp(0, 100);
  }
}
