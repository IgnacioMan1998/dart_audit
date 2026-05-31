import 'dart:io';

import 'package_downloader.dart';
import 'regex_scanner.dart';
import 'entropy_scanner.dart';

// Risk score weights by severity.
const _regexWeights = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5};
const _entropyWeights = {'HIGH': 15, 'MEDIUM': 5};

/// Full source-inspection result for a single package version.
class InspectionReport {
  const InspectionReport({
    required this.packageName,
    required this.version,
    required this.dartFileCount,
    required this.regexFindings,
    required this.entropyFindings,
    required this.riskScore,
  });

  final String packageName;
  final String version;

  /// Number of `.dart` files analyzed.
  final int dartFileCount;

  final List<RegexFinding> regexFindings;
  final List<EntropyFinding> entropyFindings;

  /// Composite risk score from 0 (clean) to 100 (highly suspicious).
  final int riskScore;

  int get criticalCount =>
      regexFindings.where((f) => f.severity == 'CRITICAL').length;
  int get highCount =>
      regexFindings.where((f) => f.severity == 'HIGH').length +
      entropyFindings.where((f) => f.severity == 'HIGH').length;
  int get mediumCount =>
      regexFindings.where((f) => f.severity == 'MEDIUM').length +
      entropyFindings.where((f) => f.severity == 'MEDIUM').length;

  /// `true` if the risk score reaches the suspicious threshold (≥30).
  bool get isSuspicious => riskScore >= 30;

  /// `true` if no findings were produced.
  bool get isClean =>
      regexFindings.isEmpty && entropyFindings.isEmpty;

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
      };
}

/// Orchestrates download and parallel scanning of a pub.dev package.
class PackageInspector {
  PackageInspector({
    PackageDownloader? downloader,
    RegexScanner? regexScanner,
    EntropyScanner? entropyScanner,
  })  : _downloader = downloader ?? PackageDownloader(),
        _regexScanner = regexScanner ?? RegexScanner(),
        _entropyScanner = entropyScanner ?? EntropyScanner();

  final PackageDownloader _downloader;
  final RegexScanner _regexScanner;
  final EntropyScanner _entropyScanner;

  /// Downloads [packageName] at [version], runs both scanners in parallel,
  /// and returns a full [InspectionReport].
  ///
  /// An optional [onStatus] callback receives progress messages.
  Future<InspectionReport> inspect(
    String packageName,
    String version, {
    void Function(String status)? onStatus,
  }) async {
    final sourceDir = await _downloader.download(
      packageName,
      version,
      onStatus: onStatus,
    );

    try {
      onStatus?.call('Scanning source files...');

      // Count Dart files before scanning.
      final dartFiles = await sourceDir
          .list(recursive: true)
          .where((e) => e is File && e.path.endsWith('.dart'))
          .length;

      // Run both scanners in parallel.
      final results = await Future.wait([
        _regexScanner.scan(sourceDir),
        _entropyScanner.scan(sourceDir),
      ]);

      final regexFindings = results[0] as List<RegexFinding>;
      final entropyFindings = results[1] as List<EntropyFinding>;

      return InspectionReport(
        packageName: packageName,
        version: version,
        dartFileCount: dartFiles,
        regexFindings: regexFindings,
        entropyFindings: entropyFindings,
        riskScore: _calculateRiskScore(regexFindings, entropyFindings),
      );
    } finally {
      // Always clean up the temp directory.
      await sourceDir.delete(recursive: true);
    }
  }

  static int _calculateRiskScore(
    List<RegexFinding> regex,
    List<EntropyFinding> entropy,
  ) {
    var score = 0;

    for (final f in regex) {
      score += _regexWeights[f.severity] ?? 5;
    }
    for (final f in entropy) {
      score += _entropyWeights[f.severity] ?? 0;
    }

    return score.clamp(0, 100);
  }
}
