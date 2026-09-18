import 'dart:io';

import 'package:yaml/yaml.dart';

import 'inspector/package_inspector.dart';
import 'inspector/trust_scorer.dart';
import 'inspector/typosquat_detector.dart';

/// Result of a safe package addition operation.
class SafeAddResult {
  const SafeAddResult({
    required this.packageName,
    required this.version,
    required this.isClean,
    required this.installed,
    this.typosquatFindings = const [],
    this.trustInfo,
    this.inspectionReport,
    this.errorMessage,
  });

  final String packageName;
  final String? version;
  final bool isClean;
  final bool installed;
  final List<TyposquatFinding> typosquatFindings;
  final PackageTrustInfo? trustInfo;
  final InspectionReport? inspectionReport;
  final String? errorMessage;
}

/// Helper to safely inspect and add a package to a Dart/Flutter project.
class SafePackageAdder {
  SafePackageAdder({
    TrustScorer? trustScorer,
    PackageInspector? inspector,
    TyposquatDetector? typosquatDetector,
  })  : _trustScorer = trustScorer ?? TrustScorer(),
        _inspector = inspector ?? PackageInspector(),
        _typosquatDetector = typosquatDetector ?? TyposquatDetector();

  final TrustScorer _trustScorer;
  final PackageInspector _inspector;
  final TyposquatDetector _typosquatDetector;

  /// Audits [packageName] and, if clean (or if [force] is true), installs it
  /// using `dart pub add` / `flutter pub add`.
  Future<SafeAddResult> addPackage({
    required String packageName,
    String? versionConstraint,
    bool isDev = false,
    bool force = false,
    void Function(String status)? onStatus,
  }) async {
    onStatus?.call('Checking typosquatting indicators...');
    final typosquatFindings = _typosquatDetector.analyze([packageName]);
    final hasTyposquatRisk = typosquatFindings.any(
      (f) => f.severity == 'CRITICAL' || f.severity == 'HIGH',
    );

    onStatus?.call('Fetching trust metadata from pub.dev...');
    PackageTrustInfo? trustInfo;
    try {
      trustInfo = await _trustScorer.assess(packageName);
    } on TrustScorerException catch (error) {
      return SafeAddResult(
        packageName: packageName,
        version: versionConstraint,
        isClean: false,
        installed: false,
        errorMessage: 'Could not complete the trust assessment: ${error.message}',
      );
    } catch (error) {
      return SafeAddResult(
        packageName: packageName,
        version: versionConstraint,
        isClean: false,
        installed: false,
        errorMessage: 'Could not complete the trust assessment: $error',
      );
    }
    if (trustInfo == null) {
      return SafeAddResult(
        packageName: packageName,
        version: versionConstraint,
        isClean: false,
        installed: false,
        errorMessage: 'Package "$packageName" was not found on pub.dev.',
      );
    }

    if (versionConstraint != null && !_isExactVersion(versionConstraint)) {
      return SafeAddResult(
        packageName: packageName,
        version: versionConstraint,
        isClean: false,
        installed: false,
        trustInfo: trustInfo,
        typosquatFindings: typosquatFindings,
        errorMessage: 'Version constraints are not supported by safe add. Use an exact version so the audited source matches the installed package.',
      );
    }

    final targetVersion = versionConstraint ?? trustInfo.version;
    if (targetVersion == null || targetVersion.isEmpty) {
      return SafeAddResult(
        packageName: packageName,
        version: versionConstraint,
        isClean: false,
        installed: false,
        trustInfo: trustInfo,
        typosquatFindings: typosquatFindings,
        errorMessage: 'pub.dev did not provide a version to inspect.',
      );
    }

    InspectionReport? inspectionReport;
    onStatus?.call('Downloading & inspecting source for $packageName $targetVersion...');
    try {
      inspectionReport = await _inspector.inspect(
        packageName,
        targetVersion,
        onStatus: onStatus,
      );
    } catch (error) {
      return SafeAddResult(
        packageName: packageName,
        version: targetVersion,
        isClean: false,
        installed: false,
        typosquatFindings: typosquatFindings,
        trustInfo: trustInfo,
        errorMessage: 'Could not complete source inspection: $error',
      );
    }

    final hasTrustRisk = !trustInfo.isTrusted;
    final hasInspectRisk = inspectionReport.isSuspicious;
    final isClean = !hasTyposquatRisk && !hasTrustRisk && !hasInspectRisk;

    if (!isClean && !force) {
      return SafeAddResult(
        packageName: packageName,
        version: targetVersion,
        isClean: false,
        installed: false,
        typosquatFindings: typosquatFindings,
        trustInfo: trustInfo,
        inspectionReport: inspectionReport,
        errorMessage: 'Security audit flagged potential risks for package "$packageName". Use --force to install anyway.',
      );
    }

    onStatus?.call('Executing pub add...');
    final installed = _runPubAdd(
      packageName: packageName,
      versionConstraint: versionConstraint,
      isDev: isDev,
    );

    return SafeAddResult(
      packageName: packageName,
      version: targetVersion,
      isClean: isClean,
      installed: installed,
      typosquatFindings: typosquatFindings,
      trustInfo: trustInfo,
      inspectionReport: inspectionReport,
      errorMessage: installed ? null : 'Failed to execute pub add command.',
    );
  }

  bool _isExactVersion(String value) {
    return RegExp(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')
        .hasMatch(value);
  }

  bool _runPubAdd({
    required String packageName,
    String? versionConstraint,
    required bool isDev,
  }) {
    final pubspecFile = File('pubspec.yaml');
    var isFlutter = false;
    if (pubspecFile.existsSync()) {
      try {
        final content = pubspecFile.readAsStringSync();
        final doc = loadYaml(content);
        if (doc is YamlMap) {
          final deps = doc['dependencies'] as YamlMap?;
          if (deps != null && deps.containsKey('flutter')) {
            isFlutter = true;
          }
        }
      } catch (_) {}
    }

    final executable = isFlutter ? 'flutter' : 'dart';
    final pkgArg = (versionConstraint != null && versionConstraint.isNotEmpty)
        ? '$packageName:$versionConstraint'
        : packageName;

    final args = [
      'pub',
      'add',
      if (isDev) '--dev',
      pkgArg,
    ];

    try {
      final result = Process.runSync(executable, args);
      return result.exitCode == 0;
    } on ProcessException {
      return false;
    }
  }
}
